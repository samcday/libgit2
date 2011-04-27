#ifndef INCLUDE_pack_indexer_h__
#define INCLUDE_pack_indexer_h__

#include "git2/pack_indexer.h"
#include "vector.h"
#include "hash.h"
#include "fileops.h"

struct git_pack_indexer {
	git_repository *repo;
	git_vector entries;
	git_oid *pack_hash;
	git_hash_ctx *pack_hash_ctx;
	git_file tmp_pack_fd;
	unsigned direct:1;

	void *previous_chunk;
	int previous_chunk_offset;
	int previous_chunk_size;
	void *current_chunk;
	int current_chunk_offset;
	int current_chunk_size;
};

#endif
