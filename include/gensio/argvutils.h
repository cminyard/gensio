/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

/*
 * A lot of things mess with converting strings to argvs, so make this
 * public.
 */

#ifndef GENSIO_ARGVUTILS_H
#define GENSIO_ARGVUTILS_H

/*
 * Separate out a string into an argv array, returning the argc/argv
 * values given.  Returns -ENOMEM when out of memory or -EINVAL if
 * there is something wrong with the string.  seps is a list of
 * separators, parameters will be separated by that vlaue.  If seps is
 * NULL it will default to the equivalent of isspace().  The argv
 * array must be freed with str_to_argv_free().
 *
 * argc may be NULL if you don't care.
 *
 * The "const" in argv is unfortunate, really a weakness in the C
 * specification.  The functions in gensio that take this are all
 * "const char * const argv[]", which means that it's not changing the
 * const array or the values in the strings, but the compiler
 * complains if you pass a "char **" into that.
 */
int str_to_argv(const char *s, int *argc, const char ***argv,
		const char *seps);

/*
 * Like the above, but allows a set of characters to be specified that
 * end the sequence, in "endchars".  If the scanner encounters one of
 * those characters outside of an escape or quotes, it will terminate
 * the scan.  If nextptr is not NULL, it sets it to a pointer to after
 * the end character if the end character was encountered, or sets it
 * to NULL if the end character was not encountered.
 */
int str_to_argv_endchar(const char *ins,
			int *r_argc, const char ***r_argv,
			const char *seps, const char *endchars,
			const char **nextptr);

/*
 * Copy an argv array.  The source does not have to be from str_to_argv
 * and must be NULL terminated.
 */
int argv_copy(const char * const oargv[],
	      int *r_argc, const char ***r_argv);

/* Free the return of str_to_argv */
void str_to_argv_free(const char **argv);

#endif /* GENSIO_ARGVUTILS_H */
