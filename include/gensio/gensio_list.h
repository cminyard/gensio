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

#ifndef GENSIO_LIST_H
#define GENSIO_LIST_H

#include <stddef.h>

#define gensio_container_of(ptr, type, member)		\
    ((type *)(((char *) ptr) - offsetof(type, member)))

/*
 * Generic doubly-linked list operations.
 */
struct gensio_list;
struct gensio_link {
    struct gensio_list *list;
    struct gensio_link *next;
    struct gensio_link *prev;
};

struct gensio_list {
    struct gensio_link link;
};

void gensio_list_rm(struct gensio_list *list, struct gensio_link *link);
void gensio_list_add_head(struct gensio_list *list, struct gensio_link *link);
void gensio_list_add_tail(struct gensio_list *list, struct gensio_link *link);
void gensio_list_add_next(struct gensio_list *list, struct gensio_link *curr,
			  struct gensio_link *link);
void gensio_list_add_prev(struct gensio_list *list, struct gensio_link *curr,
			  struct gensio_link *link);
void gensio_list_init(struct gensio_list *list);
bool gensio_list_empty(struct gensio_list *list);

#define gensio_list_first(list) ((list)->link.next)
#define gensio_list_last(list) ((list)->link.prev)
/* Go to the next entry, returning NULL if at the end. */
#define gensio_list_next(list, linkv) ((linkv)->next == &(list)->link ? \
				       NULL : (linkv)->next)
/* Go to the next entry, wrapping around to the first entry if at end. */
#define gensio_list_next_wrap(list, linkv) ((linkv)->next == &(list)->link ? \
					    (list)->link.next : (linkv)->next)

#define gensio_list_for_each(list, l)					\
    for ((l) = (list)->link.next; (l) != &(list)->link; l = l->next)

#define gensio_list_for_each_safe(list, l, l2) \
    for ((l) = (list)->link.next, (l2) = (l)->next; \
	 (l) != &(list)->link; (l) = (l2), (l2) = (l)->next )

#endif /* GENSIO_LIST_H */
