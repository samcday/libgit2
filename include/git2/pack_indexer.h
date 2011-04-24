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

#ifndef INCLUDE_git_pack_indexer_h__
#define INCLUDE_git_pack_indexer_h__

#include "common.h"
#include "types.h"
#include "oid.h"

/**
 * @file git2/pack_indexer.h
 * @brief Git packfile indexing functions
 * @defgroup git_pack_indexer Packfile indexing API
 * @ingroup Git
 * @{
 */
GIT_BEGIN_DECL

/**
 * Create a new packfile indexer. An indexer created in this fashion will expect
 * to be provided with raw packfile data to be processed and indexed. The
 * indexer must be free'd by the caller when it is no longer needed.
 * @param indexer The pointer for the new indexer.
 * @return GIT_SUCCESS on success, error otherwise.
 */
GIT_EXTERN(int) git_pack_indexer_create(git_pack_indexer **indexer);

/**
 * Create a new packfile indexer. A direct indexer will expect to be provided
 * entries via git_pack_indexer_add. The indexer must be free'd by the caller
 * when it is no longer needed.
 * @param indexer The pointer for the new indexer.
 * @return GIT_SUCCESS on success, error otherwise.
 */
GIT_EXTERN(int) git_pack_indexer_create(git_pack_indexer **indexer);

/**
 * Frees a previously allocated pack indexer.
 * @param indexer Pointer to the indexer to be freed.
 */
GIT_EXTERN(void) git_pack_indexer_free(git_pack_indexer *indexer);

GIT_EXTERN(int) git_pack_indexer_add(git_pack_indexer *indexer, git_oid *id,
		uint32_t crc, off_t offset);

GIT_EXTERN(int) git_pack_indexer_build(git_pack_indexer *indexer, void **data,
		size_t *len);

GIT_EXTERN(int) git_pack_indexer_packhash(git_pack_indexer* indexer, git_oid *pack_hash);

GIT_EXTERN(int) git_pack_indexer_fill(git_pack_indexer* indexer,
		const void *data, size_t length);

GIT_END_DECL

#endif
