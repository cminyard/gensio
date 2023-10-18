#include <stdio.h>
#include <assert.h>
#include <gensio/gensio_os_funcs_public.h>
#include <gensio/gensio_utils.h>

typedef void (*gensio_rust_log_func)(const char *log, void *data);

struct gensio_rust_os_func_data {
    void (*log_func)(const char *log, void *data);
    void *log_func_data;
};

static struct gensio_rust_os_func_data *
gensio_rust_get_data(struct gensio_os_funcs *o)
{
    struct gensio_rust_os_func_data *d = gensio_os_funcs_get_data(o);

    if (!d) {
	d = gensio_os_funcs_zalloc(o, sizeof(*d));
	gensio_os_funcs_set_data(o, d);
    }
    assert(d);
    return d;
}

static void
i_vlog_handler(struct gensio_os_funcs *o,
	       enum gensio_log_levels level,
	       const char *log, va_list args)
{
    struct gensio_rust_os_func_data *d = gensio_rust_get_data(o);
    char logstr[256];
    int pos;
    gensio_rust_log_func func = d->log_func;

    if (!func)
	return;
    pos = snprintf(logstr, sizeof(logstr), "%s: ",
		   gensio_log_level_to_str(level));
    vsnprintf(logstr + pos, sizeof(logstr) - pos, log, args);
    func(logstr, d->log_func_data);
}

void
gensio_rust_set_log(struct gensio_os_funcs *o,
		    gensio_rust_log_func func, void *data)
{
    struct gensio_rust_os_func_data *d;

    if (!func) {
	gensio_os_funcs_set_vlog(o, NULL);
	return;
    }

    d = gensio_rust_get_data(o);
    d->log_func = func;
    d->log_func_data = data;
    gensio_os_funcs_set_vlog(o, i_vlog_handler);
}

void
gensio_rust_cleanup(struct gensio_os_funcs *o)
{
    struct gensio_rust_os_func_data *d = gensio_os_funcs_get_data(o);

    if (d)
	gensio_os_funcs_zfree(o, d);
}
