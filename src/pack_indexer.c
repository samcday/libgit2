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
	return git_oid_cmp(&a->sha1, &b->sha1);
}

static int create_indexer(int is_direct, git_pack_indexer **indexer_out) {
	git_pack_indexer *indexer;

	indexer = git__malloc(sizeof(git_pack_indexer));

	if(indexer == NULL) {
		return GIT_ENOMEM;
	}

	memset(indexer, 0, sizeof(git_pack_indexer));

	indexer->direct = is_direct;
	git_vector_in
	*indexer_out = indexer;
	return GIT_SUCCESS;
}

int git_pack_indexer_create(git_pack_indexer **indexer_out) {
	return create_indexer(0, indexer_out);
}

int git_pack_indexer_create_direct(git_pack_indexer **indexer_out) {
	return create_indexer(1, indexer_out);
}

int git_pack_indexer_free(git_pack_indexer *indexer) {
	free(indexer);
}

int git_pack_indexer_add(git_pack_indexer *indexer, git_oid *id,
		uint32_t crc, off_t offset) {

}
