/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * This file defines general OS internal handling.  It's not really a
 * public include file, and is subject to change, but it useful if you
 * write your own OS handler.
 */

#ifndef GENSIO_OSOPS_ENV_H
#define GENSIO_OSOPS_ENV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>

/*
 * Functions for dealing with system environment variables.
 */

/*
 * Get the current value for the given environment variable into rval.
 * len should point to the number of bytes in rval (including the
 * terminating nil char).  It will be updated to be the number of
 * bytes in the return value of rval, not including the terminating
 * nil character.
 *
 * If the length of rval is not enough to hold the variable, this will
 * return GE_TOOBIG and len will be set to the number of bytes
 * required to hold the variable, not including the terminating nil
 * character.
 *
 * Returns GE_NOTFOUND if the environment variable does not exist.
 */
GENSIO_DLL_PUBLIC
int gensio_os_env_get(const char *name, char *rval, gensiods *len);

/*
 * Set the given environment variable to the given value.  If it
 * exists it will be overwritten.  If val is NULL the variable is
 * deleted from the environment.
 */
GENSIO_DLL_PUBLIC
int gensio_os_env_set(const char *name, const char *val);

/*
 * Return the environment variable in a newly allocated block of
 * memory.  Free it with o->free() when you are done with it.
 */
GENSIO_DLL_PUBLIC
int gensio_os_env_getalloc(struct gensio_os_funcs *o,
			   const char *name, char **rval);

/*
 * Return the current environment as an argv array.  You can then
 * modify it with the below functions.  Free it with
 * gensio_argv_free() when you are done.
 */
GENSIO_DLL_PUBLIC
int gensio_os_argvenv_alloc(struct gensio_os_funcs *o,
			    const char ***argv, gensiods *args, gensiods *argc);

/*
 * Get/set values in an argv env array.  These work like the
 * gensio_os_env_xxx() functions.
 */
GENSIO_DLL_PUBLIC
int gensio_os_argvenv_get(struct gensio_os_funcs *o,
			  const char **argv,
			  const char *name, char *rval, gensiods *len);
GENSIO_DLL_PUBLIC
int gensio_os_argvenv_set(struct gensio_os_funcs *o,
			  const char ***argv, gensiods *args, gensiods *argc,
			  const char *name, const char *val);
GENSIO_DLL_PUBLIC
int gensio_os_argvenv_getalloc(struct gensio_os_funcs *o,
			       const char **argv,
			       const char *name, char **rval);

#ifdef __cplusplus
}
#endif
#endif /* GENSIO_OSOPS_H */
