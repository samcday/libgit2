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
#ifndef INCLUDE_git_config_h__
#define INCLUDE_git_config_h__

#include "common.h"
#include "types.h"

/**
 * @file git2/config.h
 * @brief Git config management routines
 * @defgroup git_config Git config management routines
 * @ingroup Git
 * @{
 */
GIT_BEGIN_DECL

/**
 * Open a configuration file
 *
 * @param cfg_out pointer to the configuration data
 * @param path where to load the confiration from
 */
GIT_EXTERN(int) git_config_open(git_config **cfg_out, const char *path);

/**
 * Free the configuration and its associated memory
 *
 * @param cfg the configuration to free
 */
GIT_EXTERN(void) git_config_free(git_config *cfg);

/**
 * Get the value of an integer config variable.
 *
 * @param cfg where to look for the variable
 * @param name the variable's name
 * @param out pointer to the variable where the value should be stored
 * @return GIT_SUCCESS on success; error code otherwise
 */
GIT_EXTERN(int) git_config_get_int(git_config *cfg, const char *name, int *out);

/**
 * Get the value of a boolean config variable.
 *
 * This function uses the usual C convention of 0 being false and
 * anything else true.
 *
 * @param cfg where to look for the variable
 * @param name the variable's name
 * @param out pointer to the variable where the value should be stored
 * @return GIT_SUCCESS on success; error code otherwise
 */
GIT_EXTERN(int) git_config_get_bool(git_config *cfg, const char *name, int *out);

/**
 * Get the value of a string config variable.
 *
 * The string is owned by the variable and should not be freed by the
 * user.
 *
 * @param cfg where to look for the variable
 * @param name the variable's name
 * @param out pointer to the variable's value
 * @return GIT_SUCCESS on success; error code otherwise
 */
GIT_EXTERN(int) git_config_get_string(git_config *cfg, const char *name, const char **out);

/**
 * Set the value of an integer config variable.
 *
 * @param cfg where to look for the variable
 * @param name the variable's name
 * @param out pointer to the variable where the value should be stored
 * @return GIT_SUCCESS on success; error code otherwise
 */
GIT_EXTERN(int) git_config_set_int(git_config *cfg, const char *name, int value);

/**
 * Set the value of a boolean config variable.
 *
 * @param cfg where to look for the variable
 * @param name the variable's name
 * @param value the value to store
 * @return GIT_SUCCESS on success; error code otherwise
 */
GIT_EXTERN(int) git_config_set_bool(git_config *cfg, const char *name, int value);

/**
 * Set the value of a string config variable.
 *
 * A copy of the string is made and the user is free to use it
 * afterwards.
 *
 * @param cfg where to look for the variable
 * @param name the variable's name
 * @param value the string to store.
 * @return GIT_SUCCESS on success; error code otherwise
 */
GIT_EXTERN(int) git_config_set_string(git_config *cfg, const char *name, const char *value);

/**
 * Perform an operation on each config variable.
 *
 * The callback is passed a pointer to a config variable name and the
 * data pointer passed to this function. As soon as one of the
 * callback functions returns something other than 0, this function
 * returns that value.
 *
 * @param cfg where to get the variables from
 * @param callback the function to call on each variable
 * @param data the data to pass to the callback
 * @return GIT_SUCCESS or the return value of the callback which didn't return 0
 */
GIT_EXTERN(int) git_config_foreach(git_config *cfg, int (*callback)(const char *, void *data), void *data);

/** @} */
GIT_END_DECL
#endif
