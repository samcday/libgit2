/*
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
 *
 * In addition to the permissions in the GNU General Public License,
 * the authors give you unlimited permission to link the compiled
 * version of this file into combinations with other programs,
 * and to distribute those combinations without any restriction
 * coming from the use of this file.  (The General Public License
 * restrictions do apply in other respects; for example, they cover
 * modification of the file, and distribution when not linked into
 * a combined executable.)
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "common.h"
#include "pack_indexer.h"

#define PACK_VERSION 2
#define PACK_IDX_SIGNATURE 0xff744f63	/* "\377tOc" */

struct pack_index_entry {
	git_oid id;
	uint32_t crc;
	off_t offset;
};

static int pack_entries_sort_cb(const void *a_, const void *b_)
{
	struct pack_index_entry *a = *((struct pack_index_entry **)a_);
	struct pack_index_entry *b = *((struct pack_index_entry **)b_);

	// Sort by the sha1 yo.
	return git_oid_cmp(&a->id, &b->id);
}

static int create_indexer(int is_direct, git_pack_indexer **indexer_out) {
	git_pack_indexer *indexer;
	int error;

	indexer = git__malloc(sizeof(git_pack_indexer));

	if(indexer == NULL) {
		return GIT_ENOMEM;
	}

	memset(indexer, 0, sizeof(git_pack_indexer));

	indexer->direct = is_direct;
	if((error = git_vector_init(&indexer->entries, 0, pack_entries_sort_cb)) != GIT_SUCCESS) {
		return error;
	}

	if(!is_direct) {
		indexer->pack_hash_ctx = git_hash_new_ctx();
		if(indexer->pack_hash_ctx == NULL) {
			git_vector_free(&indexer->entries);
			free(indexer);
			return GIT_ENOMEM;
		}
	}

	*indexer_out = indexer;
	return GIT_SUCCESS;
}

int git_pack_indexer_create(git_pack_indexer **indexer_out) {
	return create_indexer(0, indexer_out);
}

int git_pack_indexer_create_direct(git_pack_indexer **indexer_out) {
	return create_indexer(1, indexer_out);
}

void git_pack_indexer_free(git_pack_indexer *indexer) {
	free(indexer);
}

int git_pack_indexer_add(git_pack_indexer *indexer, git_oid *id,
		uint32_t crc, off_t offset) {
	struct pack_index_entry *entry;
	int error;

	entry = git__malloc(sizeof(struct pack_index_entry));
	if(entry == NULL) {
		return GIT_ENOMEM;
	}

	git_oid_cpy(&entry->id, id);

	entry->crc = crc;
	entry->offset = offset;

	if((error = git_vector_insert(&indexer->entries, entry)) != GIT_SUCCESS) {
		free(entry);
		return GIT_ENOMEM;
	}

	return GIT_SUCCESS;
}

int git_pack_indexer_packhash(git_pack_indexer* indexer, git_oid *pack_hash) {
	// We should not be provided pack hash when we're running in raw mode.
	if(!indexer->direct) {
		return GIT_EPACKINDEXERISNOTDIRECT;
	}

	if(indexer->pack_hash != NULL) {
		free(indexer->pack_hash);
	}

	indexer->pack_hash = git__malloc(GIT_OID_RAWSZ);

	if(indexer->pack_hash == NULL) {
		return GIT_ENOMEM;
	}

	git_oid_cpy(indexer->pack_hash, pack_hash);

	return GIT_SUCCESS;
}

int git_pack_indexer_build(git_pack_indexer *indexer, void **data_out,
		size_t *len_out) {
	size_t len;
	uint32_t num_entries;
	void *data;
	uint32_t *index_header;
	uint32_t *index_offsets;
	uint32_t *index_fanout;
	git_oid *index_shas;
	uint32_t *index_crcs;
	git_oid *index_trailing_shas;
	struct pack_index_entry *entry;
	uint32_t i;
	int j;
	short fanout;
	git_hash_ctx *hash_ctx = NULL;

	// Need packfile hash. Will have this if a valid packfile was fed in, or if
	// it was explicitly provided for a direct indexing process.
	if(indexer->pack_hash == NULL) {
		return GIT_EPACKINDEXERHASHUNKNOWN;
	}

	num_entries = indexer->entries.length;

	len = 8 +							// header
				(256 * 4) + 			// fanout
				(num_entries * 20) + 	// sha1
				(num_entries * 4) + 	// crc
				(num_entries * 4) + 	// packfile offsets
				(0) + 					// 64b_offsets.
				(2 * 20); 				// trailing sha1s.

	data = git__malloc(len);

	if(data == NULL) {
		return GIT_ENOMEM;
	}


	// Time to start writing the index. We're writing out a version 2 packfile
	// index. We begin with the index header.
	index_header = data;
	*(index_header++) = htonl(PACK_IDX_SIGNATURE);
	*(index_header++) = htonl(PACK_VERSION);

	// Let's setup some quick shortcuts to relevant parts of the index.
	index_offsets = data + 8 + (256 * 4) + (num_entries * 20) + (num_entries * 4);
	index_shas = data + 8 + (256 * 4);
	index_fanout = data + 8;
	index_crcs = data + 8 + (256 * 4) + (num_entries * 20);
	index_trailing_shas = data + len - (GIT_OID_RAWSZ * 2);

	// We now write out all the sha1s, their crcs and their offsets. While we do
	// this we are also writing out the fanout table.
	git_vector_sort(&indexer->entries);
	fanout = 0;
	for(i = 0; i < num_entries; i++) {
		entry = git_vector_get(&indexer->entries, i);

		index_offsets[i] = htonl(entry->offset);
		index_shas[i] = entry->id;
		index_crcs[i] = entry->crc;

		if(entry->id.id[0] > fanout) {
			if(fanout > -1) {
				for(j = fanout; j < entry->id.id[0]; j++) {
					index_fanout[j] = htonl(i);
				}
			}

			fanout = entry->id.id[0];
		}
	}

	// Final steps, write out the trailing sha1 hashes. First one is the hash of
	// the packfile. Second is the hash of the index, including the first hash.
	memcpy(index_trailing_shas++, indexer->pack_hash, GIT_OID_RAWSZ);

	git_hash_init(hash_ctx);
	git_hash_update(hash_ctx, data, len - GIT_OID_RAWSZ);
	git_hash_final(index_trailing_shas, hash_ctx);

	// Done!
	*data_out = data;
	*len_out = len;

	return GIT_SUCCESS;
}

int git_pack_indexer_fill(git_pack_indexer* indexer, const void *data, size_t length) {
	// First thing we can do with this data is hash it for final pack file hash.
	git_hash_update(indexer->pack_hash_ctx, data, length);



	return GIT_SUCCESS;
}
