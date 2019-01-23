#ifndef IOINFO_H
#define IOINFO_H

#include <stdarg.h>
#include <gensio/gensio.h>

struct ioinfo;

struct ioinfo_sub_handlers {
    int (*handle_data)(struct gensio *io, int event,
		       unsigned char *buf, gensiods *buflen);
    bool (*handle_escape)(struct ioinfo *ioinfo, char c);
    void (*handle_multichar_escape)(struct ioinfo *ioinfo, char *escape_data);
};

struct ioinfo_user_handlers {
    void (*shutdown)(struct ioinfo *ioinfo);
    void (*err)(struct ioinfo *ioinfo, char *fmt, va_list va);
    void (*out)(struct ioinfo *ioinfo, char *fmt, va_list va);
};

struct gensio *ioinfo_otherio(struct ioinfo *ioinfo);
void *ioinfo_subdata(struct ioinfo *ioinfo);
void *ioinfo_othersubdata(struct ioinfo *ioinfo);

void *ioinfo_userdata(struct ioinfo *ioinfo);
void ioinfo_set_otherioinfo(struct ioinfo *ioinfo, struct ioinfo *otherioinfo);

void ioinfo_set_ready(struct ioinfo *ioinfo, struct gensio *io);

void ioinfo_out(struct ioinfo *ioinfo, char *fmt, ...);
void ioinfo_err(struct ioinfo *ioinfo, char *fmt, ...);

struct ioinfo *alloc_ioinfo(struct gensio_os_funcs *o,
			    char escape_char,
			    struct ioinfo_sub_handlers *sh, void *subdata,
			    struct ioinfo_user_handlers *uh, void *userdata);
void free_ioinfo(struct ioinfo *ioinfo);

#endif /* IOINFO_H */
