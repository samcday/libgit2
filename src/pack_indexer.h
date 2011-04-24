#ifndef INCLUDE_pack_indexer_h__
#define INCLUDE_pack_indexer_h__

#include "git2/pack_indexer.h"
#include "vector.h"
#include "hash.h"

struct git_pack_indexer {
	git_vector entries;
	git_oid *pack_hash;
	git_hash_ctx *pack_hash_ctx;
	unsigned direct:1;
};

#endif
