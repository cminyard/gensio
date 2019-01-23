#ifndef SER_IOINFO_H
#define SER_IOINFO_H

#include "ioinfo.h"

void *alloc_ser_ioinfo(struct gensio_os_funcs *o,
		       const char *signature,
		       struct ioinfo_sub_handlers **sh);

void free_ser_ioinfo(void *subdata);

#endif /* SER_IOINFO_H */
