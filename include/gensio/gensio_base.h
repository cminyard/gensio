/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_BASE_H
#define GENSIO_BASE_H

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>

struct gensio_filter;

typedef int (*gensio_ul_filter_data_handler)(void *cb_data,
					     gensiods *rcount,
					     const struct gensio_sg *sg,
					     gensiods sglen,
					     const char *const *auxdata);

typedef int (*gensio_ll_filter_data_handler)(void *cb_data,
					     gensiods *rcount,
					     unsigned char *buf,
					     gensiods buflen,
					     const char *const *auxdata);

/*
 * The filter has some asynchronously generated data that it needs to
 * send, tell the gensio base to recalculate its enables.
 */
#define GENSIO_FILTER_CB_OUTPUT_READY	1

/*
 * Tell gensio base to start it's timer and call the timeout
 * at the appropriate interval.
 * timeout => data (a pointer to gensio_time)
 */
#define GENSIO_FILTER_CB_START_TIMER	2

/*
 * Tell gensio base to stop it's timer.
 */
#define GENSIO_FILTER_CB_STOP_TIMER	3

/*
 * Run a control on the child.
 */
struct gensio_filter_cb_control_data {
    int depth;
    bool get;
    unsigned int option;
    char *data;
    gensiods *datalen;
};
#define GENSIO_FILTER_CB_CONTROL	4

/*
 * During open, check_open_done needs to be called.
 */
#define GENSIO_FILTER_CB_OPEN_DONE	5

/*
 * An asynchronous event has happend where the filter is ready for
 * lower-level input again.
 */
#define GENSIO_FILTER_CB_INPUT_READY	6

typedef int (*gensio_filter_cb)(void *cb_data, int func, void *data);


/*
 * Set the callback function for the filter.
 *
 *  const struct gensio_filter_callbacks *cbs => func
 *  void *cb_data => data
 */
#define GENSIO_FILTER_FUNC_SET_CALLBACK		1
GENSIO_DLL_PUBLIC
void gensio_filter_set_callback(struct gensio_filter *filter,
				gensio_filter_cb cb, void *cb_data);

/*
 * Is there data ready to be read from the top of the filter?
 */
#define GENSIO_FILTER_FUNC_UL_READ_PENDING	2
GENSIO_DLL_PUBLIC
bool gensio_filter_ul_read_pending(struct gensio_filter *filter);

/*
 * Is there data ready to be written out of the bottom of the filter?
 */
#define GENSIO_FILTER_FUNC_LL_WRITE_PENDING	3
GENSIO_DLL_PUBLIC
bool gensio_filter_ll_write_pending(struct gensio_filter *filter);

/*
 * Is the filter expecting that data should come in the bottom?
 */
#define GENSIO_FILTER_FUNC_LL_READ_NEEDED	4
GENSIO_DLL_PUBLIC
bool gensio_filter_ll_read_needed(struct gensio_filter *filter);

/*
 * Provides a way to verify keys and such after the open is complete.
 * Returning an error will abort the connection before the open is
 * returned.
 *
 * io => data
 */
#define GENSIO_FILTER_FUNC_CHECK_OPEN_DONE	5
GENSIO_DLL_PUBLIC
int gensio_filter_check_open_done(struct gensio_filter *filter,
				  struct gensio *io);

/*
 * Attempt to start a connection on the filter.  Returns 0 on
 * immediate success.  Returns GE_INPROGRESS if the connect attempt
 * should be retried on any I/O.  Returns GE_RETRY if the connect
 * attempt should be retried after any I/O or when the timeout occurs.
 * If the is called due to a timeout occurring, was_timeout will be true.
 *
 * gensio_time *timeout => data
 * bool was_timeout => buflen
 */
#define GENSIO_FILTER_FUNC_TRY_CONNECT		6
GENSIO_DLL_PUBLIC
int gensio_filter_try_connect(struct gensio_filter *filter,
			      gensio_time *timeout,
			      bool was_timeout);

/*
 * Attempt to disconnect the filter.  Returns 0 on immediate success.
 * Returns GE_INPROGRESS if the disconnect attempt should be retried on
 * any I/O.  Returns GE_RETRY if the connect attempt should be retried
 * after any I/O or when the timeout occurs.
 * If the is called due to a timeout occurring, was_timeout will be true.
 *
 * gensio_time *timeout => data
 * bool was_timeout => buflen
 */
#define GENSIO_FILTER_FUNC_TRY_DISCONNECT	7
GENSIO_DLL_PUBLIC
int gensio_filter_try_disconnect(struct gensio_filter *filter,
				 gensio_time *timeout,
				 bool was_timeout);

/*
 * Write data into the top of the filter.  If no data is provided
 * (buf is NULL) then this will just attempt to write any pending
 * data out of the bottom of the filter into the handler.
 *
 * handler => func
 * cb_data => data
 * rcount => count
 * sg => cbuf
 * sglen => buflen
 * auxdata => buf
 */
#define GENSIO_FILTER_FUNC_UL_WRITE_SG		8
GENSIO_DLL_PUBLIC
int gensio_filter_ul_write(struct gensio_filter *filter,
			   gensio_ul_filter_data_handler handler, void *cb_data,
			   gensiods *rcount,
			   const struct gensio_sg *sg, gensiods sglen,
			   const char *const *auxdata);

/*
 * Write data into the bottom of the filter.  If no data is
 * provided (buf is NULL) then this will just attempt to write any
 * pending data out of the top of the filter into the handler.
 *
 * gensio_ll_filter_data_handler handler => func
 * void *cb_data => data
 * gensiods *rcount => count
 * buf => buf
 * buflen => buflen
 */
#define GENSIO_FILTER_FUNC_LL_WRITE		9
GENSIO_DLL_PUBLIC
int gensio_filter_ll_write(struct gensio_filter *filter,
			   gensio_ll_filter_data_handler handler, void *cb_data,
			   gensiods *rcount,
			   unsigned char *buf, gensiods buflen,
			   const char *const *auxdata);

/*
 * Report a timeout for a timer the base started.
 */
#define GENSIO_FILTER_FUNC_TIMEOUT		11
GENSIO_DLL_PUBLIC
int gensio_filter_timeout(struct gensio_filter *filter);

/*
 * Allocate data and configure the filter.
 *
 * io => data
 */
#define GENSIO_FILTER_FUNC_SETUP		12
GENSIO_DLL_PUBLIC
int gensio_filter_setup(struct gensio_filter *filter, struct gensio *io);

/*
 * Reset all internal data.
 */
#define GENSIO_FILTER_FUNC_CLEANUP		13
GENSIO_DLL_PUBLIC
void gensio_filter_cleanup(struct gensio_filter *filter);

/*
 * Free the filter.
 */
#define GENSIO_FILTER_FUNC_FREE			14
GENSIO_DLL_PUBLIC
void gensio_filter_free(struct gensio_filter *filter);

/*
 * Do a control function on the filter.  Return GE_NOTSUP if not supported.
 *
 * get => cbuf
 * option => buflen
 * data => data
 * datalen => count
 */
#define GENSIO_FILTER_FUNC_CONTROL		15
GENSIO_DLL_PUBLIC
int gensio_filter_control(struct gensio_filter *filter, bool get,
			  unsigned int option, char *data, gensiods *datalen);

/*
 * Can the filter current handle a write?  If not implemented (returns
 * GE_NOSUP), assumes true.  This can be used if the upper layer
 * enables write but there's no way for the filter to write data
 * because it's blocked on flow control.
 *
 * &val => data (pointer to a bool)
 */
#define GENSIO_FILTER_FUNC_UL_CAN_WRITE		16
GENSIO_DLL_PUBLIC
bool gensio_filter_ul_can_write(struct gensio_filter *filter);

/*
 * Does the filter have write data queued?  This is different from
 * can_write and write_pending; this means that it has data that is in
 * queue but it is not ready for write.  Basically, this is for data
 * that is queued waiting for the remote end to ack it.  This is
 * optional, if it return GE_NOSUP then it calls
 * gensio_filter_ll_write_pending() for the value.
 *
 * &val => data
 */
#define GENSIO_FILTER_FUNC_LL_WRITE_QUEUED	17
GENSIO_DLL_PUBLIC
bool gensio_filter_ll_write_queued(struct gensio_filter *filter);

/*
 * Called when an I/O error occurs from the ll.
 *
 * &err => data
 */
#define GENSIO_FILTER_FUNC_IO_ERR		18
GENSIO_DLL_PUBLIC
void gensio_filter_io_err(struct gensio_filter *filter, int err);

typedef int (*gensio_filter_func)(struct gensio_filter *filter, int op,
				  void *func, void *data,
				  gensiods *count, void *buf,
				  const void *cbuf, gensiods buflen,
				  const char *const *auxdata);

GENSIO_DLL_PUBLIC
int gensio_filter_do_event(struct gensio_filter *filter, int event, int err,
			   unsigned char *buf, gensiods *buflen,
			   const char *const *auxdata);

GENSIO_DLL_PUBLIC
struct gensio_filter *gensio_filter_alloc_data(struct gensio_os_funcs *o,
					       gensio_filter_func func,
					       void *user_data);

GENSIO_DLL_PUBLIC
void gensio_filter_free_data(struct gensio_filter *filter);

GENSIO_DLL_PUBLIC
void *gensio_filter_get_user_data(struct gensio_filter *filter);

struct gensio_ll;

typedef void (*gensio_ll_open_done)(void *cb_data, int err, void *open_data);
typedef void (*gensio_ll_close_done)(void *cb_data, void *close_data);

#define GENSIO_LL_CB_READ		1
#define GENSIO_LL_CB_WRITE_READY	2

typedef gensiods (*gensio_ll_cb)(void *cb_data, int op, int val,
				 void *buf, gensiods buflen,
				 const char *const *auxdata);

/*
 * Set the callbacks for the ll.
 *
 * cbs => cbuf
 * cb_data => buf
 */
#define GENSIO_LL_FUNC_SET_CALLBACK		1
GENSIO_DLL_PUBLIC
void gensio_ll_set_callback(struct gensio_ll *ll,
			    gensio_ll_cb cb, void *cb_data);

/*
 * Write data to the ll.
 *
 * rcount => count
 * buf => cbuf
 * buflen => buflen
 * auxdata => buf
 */
#define GENSIO_LL_FUNC_WRITE_SG			2
GENSIO_DLL_PUBLIC
int gensio_ll_write(struct gensio_ll *ll, gensiods *rcount,
		    const struct gensio_sg *sg, gensiods sglen,
		    const char *const *auxdata);

/*
 * Was FUNC_RADDR_TO_STR
 */
#define GENSIO_LL_unused1			3

/*
 * Was FUNC_GET_RADDR
 */
#define GENSIO_LL_unused2			4

/*
 * Was FUNC_REMOTE_ID
 */
#define GENSIO_LL_unused3			5

/*
 * Returns 0 if the open was immediate, EINPROGRESS if it was deferred,
 * and an errno otherwise.
 *
 * done => cbuf
 * open_data => buf
 */
#define GENSIO_LL_FUNC_OPEN			6
GENSIO_DLL_PUBLIC
int gensio_ll_open(struct gensio_ll *ll,
		   gensio_ll_open_done done, void *open_data);

/*
 * Returns 0 on success, close is always deferred.
 *
 * done => cbuf
 * close_data => buf
 */
#define GENSIO_LL_FUNC_CLOSE			7
GENSIO_DLL_PUBLIC
int gensio_ll_close(struct gensio_ll *ll,
		    gensio_ll_close_done done, void *close_data);

/*
 * enabled => buflen
 */
#define GENSIO_LL_FUNC_SET_READ_CALLBACK	8
GENSIO_DLL_PUBLIC
void gensio_ll_set_read_callback(struct gensio_ll *ll, bool enabled);

/*
 * enabled => buflen
 */
#define GENSIO_LL_FUNC_SET_WRITE_CALLBACK	9
GENSIO_DLL_PUBLIC
void gensio_ll_set_write_callback(struct gensio_ll *ll, bool enabled);

#define GENSIO_LL_FUNC_FREE			10
GENSIO_DLL_PUBLIC
void gensio_ll_free(struct gensio_ll *ll);

/*
 * option => buflen
 * get => cbuf
 * auxdata => buf
 * datalen => count
 */
#define GENSIO_LL_FUNC_CONTROL			11
GENSIO_DLL_PUBLIC
int gensio_ll_control(struct gensio_ll *ll, bool get, int option, char *data,
		      gensiods *datalen);

#define GENSIO_LL_FUNC_DISABLE			12
GENSIO_DLL_PUBLIC
void gensio_ll_disable(struct gensio_ll *ll);

typedef int (*gensio_ll_func)(struct gensio_ll *ll, int op,
			      gensiods *count,
			      void *buf, const void *cbuf,
			      gensiods buflen,
			      const char *const *auxdata);

/*
 * Get the gensio associated with the filter.
 */
GENSIO_DLL_PUBLIC
struct gensio *gensio_filter_get_gensio(struct gensio_filter *filter);

/*
 * Call the event interface of the upper layer.
 */
GENSIO_DLL_PUBLIC
int gensio_ll_do_event(struct gensio_ll *ll, int event, int err,
		       unsigned char *buf, gensiods *buflen,
		       const char *const *auxdata);

GENSIO_DLL_PUBLIC
struct gensio_ll *gensio_ll_alloc_data(struct gensio_os_funcs *o,
				       gensio_ll_func func, void *user_data);
GENSIO_DLL_PUBLIC
void gensio_ll_free_data(struct gensio_ll *ll);
GENSIO_DLL_PUBLIC
void *gensio_ll_get_user_data(struct gensio_ll *ll);
GENSIO_DLL_PUBLIC
struct gensio_ll *base_gensio_get_ll(struct gensio *io);

GENSIO_DLL_PUBLIC
struct gensio *base_gensio_alloc(struct gensio_os_funcs *o,
				 struct gensio_ll *ll,
				 struct gensio_filter *filter,
				 struct gensio *child,
				 const char *typename,
				 gensio_event cb, void *user_data);

GENSIO_DLL_PUBLIC
struct gensio *base_gensio_server_alloc(struct gensio_os_funcs *o,
					struct gensio_ll *ll,
					struct gensio_filter *filter,
					struct gensio *child,
					const char *typename,
					gensio_done_err open_done,
					void *open_data);

/*
 * base_gensio_server_alloc() does not start the gensio, you have to
 * call this.  This lets you do some gensio configuration and handle
 * errors more easily.
 */
GENSIO_DLL_PUBLIC
int base_gensio_server_start(struct gensio *io);

/*
 * Code for the generic accepter code.  This implements the state
 * machine for an accepter so you don't have to.  Basically, you
 * probably don't need locking or checks, you can just do the
 * operations specific to your gensio.
 */

/*
 * The callback code for generic gensio accepter users.
 */
typedef int (*gensio_base_acc_op)(struct gensio_accepter *acc, int op,
				  void *acc_op_data, void *done, int val1,
				  void *data, void *data2, void *ret);

/*
 * Note that all the below take an acc an dacc_op_data.  op is set to
 * the operation numbers below.
 */

/*
 * Startup the operation
 */
#define GENSIO_BASE_ACC_STARTUP		0

/*
 * Shutdown the operation and call the done callback when done.
 *
 *   done => (gensio_acc_done) done
 */
#define GENSIO_BASE_ACC_SHUTDOWN	1

/*
 * Enable the callbacks.  If done is not NULL, call the done callback
 * when the operation is complete.
 *
 *   enabled => val1
 *   done => (gensio_acc_done) done
 */
#define GENSIO_BASE_ACC_SET_CB_ENABLE	2

/*
 * Free the data
 */
#define GENSIO_BASE_ACC_FREE		3

/*
 * Disable the gensio (see other docs in disable for semantics.
 */
#define GENSIO_BASE_ACC_DISABLE		4

/*
 * gensio controls
 *
 *   done => (unsigned int *) &option
 *   val1 => get
 *   data => data
 *   ret => (gensiods *) datalen
 */
#define GENSIO_BASE_ACC_CONTROL		5

/*
 * Create a new gensio from a string.
 *
 *   done => (gensio_event) cb
 *   data => (const char *) addr
 *   data2 => user_data
 *   ret => (struct gensio **) new_io
 */
#define GENSIO_BASE_ACC_STR_TO_GENSIO	6

/*
 * When creating a new connection, call the start operation below to
 * start things up, if it returns an error then it is not in the right
 * state to accept a new connection.
 *
 * You must call the end operation without blocking when you finish
 * setting up the child (no matter what, error or not).  Pass in the
 * gensio error if you get one, zero othersize.  Note that this claims
 * and releases a lock.
 */
GENSIO_DLL_PUBLIC
int base_gensio_accepter_new_child_start(struct gensio_accepter *accepter);
GENSIO_DLL_PUBLIC
void base_gensio_accepter_new_child_end(struct gensio_accepter *accepter,
					struct gensio *io, int err);

/*
 * When a new child is completely up (or fails to come up), call this
 * function to report the new event on the gensio and handle any
 * internal cleanup.  Pass in the error if there is a failure.
 */
GENSIO_DLL_PUBLIC
void base_gensio_server_open_done(struct gensio_accepter *accepter,
				  struct gensio *net, int err);

/*
 * Allocate a new accepter.  Note that the child may be NULL if there
 * isn't one, this is just passed to the main gensio accepter
 * allocation.
 */
GENSIO_DLL_PUBLIC
int base_gensio_accepter_alloc(struct gensio_accepter *child,
			       gensio_base_acc_op ops,
			       void *acc_op_data,
			       struct gensio_os_funcs *o,
			       const char *typename,
			       gensio_accepter_event cb, void *user_data,
			       struct gensio_accepter **accepter);

/*
 * Return the acc_op_data passed in to an accepter allocated from the
 * above function.
 */
GENSIO_DLL_PUBLIC
void *base_gensio_accepter_get_op_data(struct gensio_accepter *accepter);

#endif /* GENSIO_BASE_H */
