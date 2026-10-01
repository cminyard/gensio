/* SPDX-License-Identifier: GPL-2.0-only */

/* Exercise the library directly, including reopening the same object. */
#include <stdio.h>
#include <stdlib.h>
#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>

int
main(int argc, char **argv)
{
    struct gensio_os_funcs *o = NULL;
    struct gensio *io = NULL;
    gensio_time timeout;
    gensiods count;
    unsigned char response;
    int err, i;

    if (argc != 2)
	return 2;
    err = gensio_alloc_os_funcs(0, &o, 0);
    if (err)
	return 1;
    err = str_to_gensio(argv[1], o, NULL, NULL, &io);
    if (err)
	goto out;
    for (i = 0; i < 2; i++) {
	err = gensio_set_sync(io);
	if (err)
	    goto out;
	err = gensio_open_s(io);
	if (err)
	    goto out;
	timeout.secs = 5;
	timeout.nsecs = 0;
	err = gensio_write_s(io, &count, "x", 1, &timeout);
	if (!err && count != 1)
	    err = GE_IOERR;
	if (!err) {
	    timeout.secs = 5;
	    timeout.nsecs = 0;
	    err = gensio_read_s(io, &count, &response, 1, &timeout);
	    if (!err && (count != 1 || response != 'x'))
		err = GE_IOERR;
	}
	if (err) {
	    gensio_close_s(io);
	    goto out;
	}
	err = gensio_close_s(io);
	if (err)
	    goto out;
	err = gensio_clear_sync(io);
	if (err)
	    goto out;
    }
 out:
    if (err)
	fprintf(stderr, "%s\n", gensio_err_to_str(err));
    if (io)
	gensio_free(io);
    gensio_cleanup_mem(o);
    o->free_funcs(o);
    return err ? 1 : 0;
}
