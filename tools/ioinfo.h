/*
 *  ioinfo - A program for connecting gensios.
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 *
 *  In addition, as a special exception, the copyright holders of
 *  gensio give you permission to combine gensio with free software
 *  programs or libraries that are released under the GNU LGPL and
 *  with code included in the standard release of OpenSSL under the
 *  OpenSSL license (or modified versions of such code, with unchanged
 *  license). You may copy and distribute such a system following the
 *  terms of the GNU GPL for gensio and the licenses of the other code
 *  concerned, provided that you include the source code of that
 *  other code when and as the GNU GPL requires distribution of source
 *  code.
 *
 *  Note that people who make modified versions of gensio are not
 *  obligated to grant this special exception for their modified
 *  versions; it is their choice whether to do so. The GNU General
 *  Public License gives permission to release a modified version
 *  without this exception; this exception also makes it possible to
 *  release a modified version which carries forward this exception.
 */

/*
 * ioinfo is a tool that connects two gensios together and transfers data
 * between them.
 *
 * ioinfo can watch for an escape character read from a gensio and do
 * special handling on the next character(s).  It has a plugin to
 * extend the escape character handling.
 *
 * To use this, you:
 * * (optional) Set up sub handlers for handling escape characters
 *   outside of the normal ones.
 * * Create a struct ioinfo_user_handlers for handling callbacks from
 *   ioinfo
 * * Allocate an ioinfo for each gensio and set the otherinfo so they
 *   point to each other.
 * * Allocate the gensios (or if using an accepting gensio, use the
 *   gensio each provide it.
 * * When a gensio is ready, set the ioinfo ready.  You don't have to
 *   do this for both at the same time, if you do it for one, it will
 *   not use the other until the other is ready.
 *
 * When both are ready, it will start transferring data between the
 * two gensios.
 *
 * The ioinfo handles three escape characters itself.  Any other
 * escape characters are handled by sub handlers.  If an escape
 * character is not recognized, it is ignored.  The ones handled by
 * ioinfo are:
 *
 *  * <escape char> - Send the escape char.  To send it the
 *    escape character requires entering it twice in succession.
 *  * q - Terminate the connection
 *  * b - Send a break on the other gensio.  The meaning of this
 *    depends on the other gensio, it may be ignored.
 */

#ifndef IOINFO_H
#define IOINFO_H

#include <stdarg.h>
#include <gensio/gensio.h>

struct ioinfo;

/*
 * Function calls for handling escape characters and special functions.
 */
struct ioinfo_sub_handlers {
    /*
     * Handle a gensio event that ioinfo does not handle.  This can be
     * used for special serial port handling, for instance.  Should
     * return ENOTSUP if the event handler did not handle the event.
     */
    int (*handle_event)(struct gensio *io, int event,
			unsigned char *buf, gensiods *buflen);

    /*
     * Handle an escape character.  If this returns true, then the
     * ioinfo will go into multichar mode where it collects characters
     * until it gets a \r or \n, then calls handle_multichar_escape with
     * the data.
     */
    bool (*handle_escape)(struct ioinfo *ioinfo, char c);

    /*
     * Handle a multi-character escape sequence after it has been
     * received.
     */
    void (*handle_multichar_escape)(struct ioinfo *ioinfo, char *escape_data);
};

enum ioinfo_shutdown_reason {
    IOINFO_SHUTDOWN_USER_REQ,
    IOINFO_SHUTDOWN_REMCLOSE,
    IOINFO_SHUTDOWN_ERR
};

/*
 * Function calls the user of the ioinfo must provide.
 */
struct ioinfo_user_handlers {
    /*
     * Called when an error occurs on the gensios or when escape-q is
     * received.  The user should shut down the gensios.  If user_req
     * is set, then it was due to a user command.  Otherwise it was
     * due to an I/O error from either end.
     */
    void (*shutdown)(struct ioinfo *ioinfo,
		     enum ioinfo_shutdown_reason reason);

    /*
     * Called to report an error received from the gensio.
     */
    void (*err)(struct ioinfo *ioinfo, char *fmt, va_list va);

    /*
     * Called when something in the ioinfo or sub-ioinfo wants to
     * display output to the user.  This is only used for escape
     * character handling and may be NULL if escape handling is
     * disabled.
     */
    void (*out)(struct ioinfo *ioinfo, char *fmt, va_list va);

    /*
     * Called to handle gensio events the ioinfo doesn't handle.
     * May be NULL.
     */
    int (*event)(struct ioinfo *ioinfo, struct gensio *io, int event,
		 int err, unsigned char *buf, gensiods *buflen,
		 const char *const *auxdata);

    /*
     * Called when out of band data is received.  May be NULL to ignore.
     */
    void (*oobdata)(struct ioinfo *ioinfo,
		    unsigned char *buf, gensiods *buflen);
};

/* Get the gensio. */
struct gensio *ioinfo_io(struct ioinfo *ioinfo);

/* Get the gensio for the other side of the connection. */
struct gensio *ioinfo_otherio(struct ioinfo *ioinfo);

/* Get the data for the sub handler. */
void *ioinfo_subdata(struct ioinfo *ioinfo);

/* Get the data for the other side's sub handler. */
void *ioinfo_othersubdata(struct ioinfo *ioinfo);

/* Get the user data supplied when the ioinfo was allocated. */
void *ioinfo_userdata(struct ioinfo *ioinfo);

/* Get the user data supplied when the ioinfo was allocated. */
struct ioinfo *ioinfo_otherioinfo(struct ioinfo *ioinfo);

/*
 * Set each other side's ioinfo for a connection.  Both sides are set,
 * so you only need to call this once.
 */
void ioinfo_set_otherioinfo(struct ioinfo *ioinfo, struct ioinfo *otherioinfo);

/*
 * Set the ioinfo as ready.  This sets the gensio for ioinfo, turns on
 * read for the gensio, and marks itself ready.  This means that it
 * will receive data from the gensio and from the other side.  If the
 * other side is not ready, it will drop any received data (though it
 * still does escape and sub handling).
 */
void ioinfo_set_ready(struct ioinfo *ioinfo, struct gensio *io);

/*
 * Call before close, so the ioinfo doesn't get used after close.
 */
void ioinfo_set_not_ready(struct ioinfo *ioinfo);

/* Send data to the ioinfo user's out function. */
void ioinfo_out(struct ioinfo *ioinfo, char *fmt, ...);

/* Send data to the ioinfo user's err function. */
void ioinfo_err(struct ioinfo *ioinfo, char *fmt, ...);

struct ioinfo_oob
{
    unsigned char *buf;
    gensiods len;
    void *cb_data;
    void (*send_done)(void *cb_data);

    struct ioinfo_oob *next;
};
/*
 * Send out of band data.  It will not be sent immediately, instead it
 * will be queued and send_done() will be called when the send is complete,
 * if it is not NULL.
 */
void ioinfo_sendoob(struct ioinfo *ioinfo, struct ioinfo_oob *oobinfo);

/*
 * Allocate an ioinfo.
 *
 * If escape_char >= 0, the ioinfo will monitor for that character and
 * if it see it, it will handle the next character as an escape.
 *
 * sh provides a way to plug in special handling for events and escape
 * characters.  It may be NULL, disabling the function.
 *
 * The user must provide a handler.
 */
struct ioinfo *alloc_ioinfo(struct gensio_os_funcs *o,
			    int escape_char,
			    struct ioinfo_sub_handlers *sh, void *subdata,
			    struct ioinfo_user_handlers *uh, void *userdata);

/* Free the ioinfo. */
void free_ioinfo(struct ioinfo *ioinfo);

#endif /* IOINFO_H */
