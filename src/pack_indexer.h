#ifndef INCLUDE_pack_indexer_h__
#define INCLUDE_pack_indexer_h__

#include "git2/pack_indexer.h"
#include "vector.h"

struct git_pack_indexer {
	git_vector entries;

	unsigned direct:1;
};

#endif
