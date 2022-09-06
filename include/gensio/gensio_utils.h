/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_UTILS_H
#define GENSIO_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gensio/gensioosh_dllvisibility.h>
#include <gensio/gensio_types.h>

GENSIOOSH_DLL_PUBLIC
int gensio_time_cmp(gensio_time *t1, gensio_time *t2);

/*
 * Helper functions that don't fit anywhere else.
 */

/*
 * Returns true of str is in one of auxdata, false if not.
 */
GENSIOOSH_DLL_PUBLIC
bool gensio_str_in_auxdata(const char *const *auxdata, const char *str);

/*
 * Various conversion helpers.  These may become inline someday...
 */
GENSIOOSH_DLL_PUBLIC
uint32_t gensio_buf_to_u32(unsigned char *data);
GENSIOOSH_DLL_PUBLIC
void gensio_u32_to_buf(unsigned char *data, uint32_t v);
GENSIOOSH_DLL_PUBLIC
uint16_t gensio_buf_to_u16(unsigned char *data);
GENSIOOSH_DLL_PUBLIC
void gensio_u16_to_buf(unsigned char *data, uint16_t v);

/*
 * A helper function, very useful for raddr handling.  Do an
 * snprintf() at buf + *pos, writing to up to buf + len.  If *pos > len,
 * then don't do anything, but always return the number of characters
 * that would have been output if there was enough room. Pos is updated
 * to the new location it would have been if there was enough room.
 */
GENSIOOSH_DLL_PUBLIC
gensiods gensio_pos_snprintf(char *buf, gensiods len, gensiods *pos,
			     char *format, ...);

/*
 * Like the above, but it handles converting an argv to a string, properly
 * quoting everything.
 */
GENSIOOSH_DLL_PUBLIC
gensiods gensio_argv_snprintf(char *buf, gensiods len, gensiods *pos,
			      const char **argv);

/*
 * An sprintf that allocates the memory
 */
GENSIOOSH_DLL_PUBLIC
char *gensio_alloc_vsprintf(struct gensio_os_funcs *o,
			    const char *fmt, va_list va);
GENSIOOSH_DLL_PUBLIC
char *gensio_alloc_sprintf(struct gensio_os_funcs *o,
			   const char *fmt, ...);

GENSIOOSH_DLL_PUBLIC
char *gensio_strdup(struct gensio_os_funcs *o, const char *str);

GENSIOOSH_DLL_PUBLIC
char *gensio_strndup(struct gensio_os_funcs *o, const char *str, gensiods len);

/*
 * Take the input string, put " around it, and put a \ infront of
 * every \ and ".  This allows you to take a string with " and \ in it
 * and have them pass through the str_to_gensio() and such functions
 * properly.
 */
GENSIOOSH_DLL_PUBLIC
char *gensio_quote_string(struct gensio_os_funcs *o, const char *str);

/*
 * A bitmask of log levels to tell what to log.  Defaults to fatal and err
 * only.
 */
GENSIOOSH_DLL_PUBLIC
void gensio_set_log_mask(unsigned int mask);
GENSIOOSH_DLL_PUBLIC
unsigned int gensio_get_log_mask(void);
GENSIOOSH_DLL_PUBLIC
const char *gensio_log_level_to_str(enum gensio_log_levels level);

GENSIOOSH_DLL_PUBLIC
void gensio_vlog(struct gensio_os_funcs *o, enum gensio_log_levels level,
		 const char *str, va_list args);
GENSIOOSH_DLL_PUBLIC
void gensio_log(struct gensio_os_funcs *o, enum gensio_log_levels level,
		const char *str, ...);

#ifdef __cplusplus
}
#endif
#endif /* GENSIO_UTILS_H */
