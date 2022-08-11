/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * A lot of things mess with converting strings to argvs, so make this
 * public.
 */

#ifndef GENSIO_ARGVUTILS_H
#define GENSIO_ARGVUTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>

/*
 * Separate out a string into an argv array, returning the argc/argv
 * values given.  Returns GE_NOMEM when out of memory or GE_INVAL if
 * there is something wrong with the string.  seps is a list of
 * separators, parameters will be separated by that value.  If seps is
 * NULL it will default to the equivalent of isspace().  The argv
 * array must be freed with gensio_argv_free().
 *
 * argc may be NULL if you don't care.
 *
 * The "const" in argv is unfortunate, really a weakness in the C
 * specification.  The functions in gensio that take this are all
 * "const char * const argv[]", which means that it's not changing the
 * const array or the values in the strings, but the compiler
 * complains if you pass a "char **" into that.
 */
GENSIO_DLL_PUBLIC
int gensio_str_to_argv(struct gensio_os_funcs *o,
		       const char *s, int *argc, const char ***argv,
		       const char *seps);

/*
 * Like the above, but allows a set of characters to be specified that
 * end the sequence, in "endchars".  If the scanner encounters one of
 * those characters outside of an escape or quotes, it will terminate
 * the scan.  If nextptr is not NULL, it sets it to a pointer to after
 * the end character if the end character was encountered, or sets it
 * to NULL if the end character was not encountered.
 */
GENSIO_DLL_PUBLIC
int gensio_str_to_argv_endchar(struct gensio_os_funcs *o,
			       const char *ins,
			       int *r_argc, const char ***r_argv,
			       const char *seps, const char *endchars,
			       const char **nextptr);

/*
 * Copy an argv array.  The source does not have to be from str_to_argv
 * and must be NULL terminated.  r_args may be NULL if you don't care, but
 * you must supply r_argv.
 */
GENSIO_DLL_PUBLIC
int gensio_argv_copy(struct gensio_os_funcs *o,
	      const char * const oargv[],
	      int *r_argc, const char ***r_argv);

/*
 * For creating and modifying argv structures.  Pass in a pointer to
 * a NULL argv, the function will allocate the argv and add the string.
 * You can continue to call this and add more arguments.  args and argc
 * are used to track the position and size of the array.
 *
 * Call this at the end with a NULL str to terminate the array. Note
 * that if you terminate the array like this, *argc will not be
 * incremented by the NULL addition.  So you can use *argc as the
 * number of elements in the array.
 *
 * If allocstr is true, copy the string to new allocated memory.  If
 * it is false, str must have been allocated with o->zalloc() and it
 * will be directly put into the argv.
 */
GENSIO_DLL_PUBLIC
int gensio_argv_append(struct gensio_os_funcs *o, const char ***argv,
		       const char *str, gensiods *args, gensiods *argc,
		       bool allocstr);

/*
 * Standard utilities using sprintf-type things to append arguments to
 * an argv.  The string data is always allocated.
 */
GENSIO_DLL_PUBLIC
int gensio_argv_vappend(struct gensio_os_funcs *o, const char ***argv,
			gensiods *args, gensiods *argc,
			const char *fmt, va_list ap);
GENSIO_DLL_PUBLIC
int gensio_argv_sappend(struct gensio_os_funcs *o, const char ***argv,
			gensiods *args, gensiods *argc, const char *fmt, ...);

/* Free the return of str_to_argv */
GENSIO_DLL_PUBLIC
void gensio_argv_free(struct gensio_os_funcs *o, const char **argv);

/*
 * Scan a set of gensio-like arguments separated by commas.  Handles
 * quotes properly.  If the string begins with a '(', the scan will
 * end after the matching ')'.  Otherwise it scans to the end of the
 * string.  *rstr is updated to the end of the scan.
 */
GENSIO_DLL_PUBLIC
int gensio_scan_args(struct gensio_os_funcs *o,
		     const char **rstr, int *argc, const char ***args);

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_ARGVUTILS_H */
