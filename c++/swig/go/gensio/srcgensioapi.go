//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

// Creates a more go-friendly setup for the user.  The raw interface
// has issues dealing with naming, garbage collection, etc.  This
// wraps it all for a clean interface.

package gensio

import (
	"fmt"
	"runtime"
	"reflect"
	"sync/atomic"
)

// This is the interface used to receive logs from an OS handler.
type Logger interface {
	// Callback to report a log to the user.  level is one of LOG_xxx
	// defined below, log is a string.
	Log(level int, log string)

	// Internal
	getLoggerBase() *LoggerBase
	breakLinks()
}

// The base class for logging, this *must* be the first thing in your
// structure.
type LoggerBase struct {
	Logger
	rl *rawLoggerBase
}

// Errors are available as gensio.GE_xxx, normal error names.  You can
// use this function to convert the numbers to a human-readable
// string.
func ErrToStr(err int) string { return Err_to_string(err) }

// Log levels. I couldn't find an easy way to make SWIG include these
// directly.
var LOG_FATAL int = int(GENSIO_LOG_FATAL)
var LOG_ERR int = int(GENSIO_LOG_ERR)
var LOG_WARNING int = int(GENSIO_LOG_WARNING)
var LOG_INFO int = int(GENSIO_LOG_INFO)
var LOG_DEBUG int = int(GENSIO_LOG_DEBUG)
var LOG_MASK_ALL int = (1 << LOG_FATAL | 1 << LOG_ERR | 1 << LOG_WARNING |
			1 << LOG_INFO | 1 << LOG_DEBUG)

// The global log mask for the gensio library.  By default only fatal
// and error logs are reported.
func SetLogMask(mask int) { Set_log_mask(mask) }
func GetLogMask() int { return Get_log_mask() }

// Convert a log level to a string.
func LogLevelToStr(level int) string {
	return Log_level_to_str(Gensio_log_levels(level))
}

// This is the OsFuncs structure you must pass around.
type OsFuncs struct {
	RawOs_Funcs
	l Logger // Keep a ref around to avoid GC
}

// Allocate a new OsFuncs object.  sig is the Unix signal to use for
// inter-processor alerting in multi-threaded programs.  It can be
// zero for single-threaded programs, and must be zero for non-Unix
// OSes.  l is the function to receive log messages.  It may be nil,
// and no logs will be printed.
func NewOsFuncs(sig int, l Logger) *OsFuncs {
	var o *OsFuncs
	if l == nil {
		o = &OsFuncs{NewRawOs_Funcs(sig), l}
	} else {
		o = &OsFuncs{NewRawOs_Funcs(sig, setupLogger(l)), l}
	}
	runtime.SetFinalizer(o, destroyer.destroy)
	return o
}

// Generate a log on the OsFuncs.
func (o *OsFuncs) Log(level int, log string) {
	o.Rawlog(Gensio_log_levels(level), log)
}

// A structure used to represent time.  It contains a seconds and
// nanoseconds value that you may set and get with the appropriate
// functions below.
type Time struct {
	Gensio_time
}

func NewTime(secs int64, nsecs int) *Time {
	gt := &Time{NewGensio_time(secs, nsecs)}
	runtime.SetFinalizer(gt, destroyer.destroy)
	return gt
}

func (t *Time) SetTime(secs int64, nsecs int) {
	t.Gensio_time.SetSecs(secs)
	t.Gensio_time.SetNsecs(nsecs)
}

func (t *Time) GetTime() (int64, int) {
	return t.Gensio_time.GetSecs(), t.Gensio_time.GetNsecs()
}

// An interface to represent a Gensio object.
type Gensio interface {
	// Open the given gensio and all of its children.  If od is
	// not nil, call the OpenDone() method on that object when the
	// open completes.
	Open(od GensioOpenDone)

	// Open the given gensio like Open() but do not open its
	// children.  This is useful if you are manually stacking
	// gensios on existing gensios with NewGensioChild().
	OpenNochild(od GensioOpenDone)

	// Open and wait until the open completes before returning.
	OpenS()

	// Like OpenNochild, but wait until the open is complete
	// before returning.
	OpenNochildS()

	// For a channel-oriented gensio, allocate a new channel with
	// the given arguments and callback handler.  It return a
	// Gensio object representing the new channel.
	AllocChannel(args []string, cb Event) Gensio

	// Enable the read callback for a Gensio.  You must set this
	// to true get data from the gensio in asynchronous mode.  If
	// you want to flow-control the read data, set it to false.
	SetReadCallbackEnable(val bool)

	// Enable the write ready callback for a Gensio.  Normally you
	// would have this set to false.  If you attempt to write to
	// the Gensio and it returns less than the amount you
	// requested to write, set this to true to know when you can
	// write again.
	SetWriteCallbackEnable(val bool)

	// Write the given data and auxdata to the gensio.  The
	// meaning of auxdata is gensio-specific, see the gensio.5 man
	// for infor.  Returns the number of bytes actually written.
	Write(data []byte, auxdata []string) uint64

	// Close the given gensio and all of its children.  If cd is
	// not nil, call the CloseDone() method on that object when
	// the close completes.
	Close(cd GensioCloseDone)

	// Like Close(), but waits until the close completes before
	// returning.
	CloseS()

	// Return a string type for a Gensio.  depth is the number of
	// gensios to go down in the stack to fetch the type for.  For
	// instance, if you have a gensio
	// "telnet,ssl,tcp,localhost,1234", depth 0 is "telnet", depth
	// 1 is "ssl", and depth 2 is "tcp".  This will return an
	// empty string if the depth is larger than the gensio stack.
	GetType(depth uint) string

	// Returns if the gensio is a client or server
	IsClient() bool

	// Returns if the gensio is reliable (won't lose data) or not.
	IsReliable() bool

	// Returns if the gensio is a packet gensio.  See the gensio.5
	// man page for documentation on what this means.
	IsPacket() bool

	// Returns if the gensio is message packet gensio.  See the gensio.5
	// man page for documentation on what this means.
	IsMessage() bool

	// Returns if the gensio has been authenticated.
	IsAuthenticated() bool

	// Returns if the gensio's transferred data is encrypted.
	IsEncrypted() bool

	// Enable synchronous mode.  See the gensio_sets_sync.3 man
	// page for details on what this means.
	SetSync()

	// Disable synchronous mode and set the Gensio to use normal
	// asynchronous mode.
	ClearSync()

	// Read data synchronously from the Gensio.  This will wait
	// for data on the Gensio.  See SetSync() for details; this is
	// somewhat dangerous to use if not done carefully.  If
	// timeout is not nil, wait at most the given amount of time.
	// If intr is true, return immediately if the thread receives
	// a signal.  The first return value is either 0 for data
	// being read, GE_TIMEDOUT if the operation timed out, and
	// GE_INTERRUPTED if a signal was received.  The second return
	// value is the data.
	ReadS(data []byte, timeout *Time, intr bool) (int, []byte)

	// Write data to the gensio and wait for the write to
	// complete.  See SetSync() for details; this is somewhat
	// dangerous to use if not done carefully.  If timeout is not
	// nil, wait at most the given amount of time.  If intr is
	// true, return immediately if the thread receives a signal.
	// The first return value is either 0 for data being written,
	// GE_TIMEDOUT if the operation timed out and no data was
	// written, and GE_INTERRUPTED if a signal was received and no
	// data was written.  The second return value is the number of
	// bytes actually written; it may be less than the number of
	// bytes if the operation timed out or was signalled and only
	// a partial write occurred.
	WriteS(data []byte, timeout *Time, intr bool) (int, uint64)

	// Control operations.  See the gensio_control.3 man page for
	// details.  The depth, get, and option values are per the man
	// page.  The data field is passed into the control and must
	// be large enough to hold the expected result that will be
	// returned.  The first return value is an error, this will
	// not raise a gensio_error() when it gets an error return.
	// The second return value is the result data, using the same
	// data as passed in.  The third return value is the full
	// amount of data that would be required to hold the data.  It
	// may be larger than cap(data); you can use this to determine
	// if the data is truncated.
	Control(depth int, get bool, option uint, data []byte) (int, []byte,
		uint64)

	// Set/change the event handler for a Gensio.  Useful if you
	// receive a Gensio from a NewConnection or NewChannel
	// callback.
	SetEvent(e Event)

	// Internals
	getRawGensio() RawGensio
}

type SerialGensio interface {
	Baud(baud uint, done SerialOpDone)
	Datasize(size uint, done SerialOpDone)
	Parity(par uint, done SerialOpDone)
	Stopbits(bits uint, done SerialOpDone)
	Flowcontrol(flow uint, done SerialOpDone)
	Iflowcontrol(flow uint, done SerialOpDone)
	Sbreak(sbreak uint, done SerialOpDone)
	Dtr(dtr uint, done SerialOpDone)
	Rts(rts uint, done SerialOpDone)
	Cts(cts uint, done SerialOpDone)
	Dcd_dsr(dcd_dsr uint, done SerialOpDone)
	Ri(ri uint, done SerialOpDone)
	Signature(data []byte, done SerialOpSigDone)

	// Syncrohous functions.  If you pass in a valid timeout,
	// these will return GE_TIMEDOUT on a timeout.  If you set
	// intr to true, it will return GE_INTERRUPTED if a signal
	// comes in.  On all other errors it raises an exception.

	BaudS(baud uint, timeout *Time, intr bool) (int, uint)
	DatasizeS(size uint, timeout *Time, intr bool) (int, uint)
	ParityS(par uint, timeout *Time, intr bool)(int, uint)
	StopbitsS(bits uint, timeout *Time, intr bool) (int, uint)
	FlowcontrolS(flow uint, timeout *Time, intr bool) (int, uint)
	IflowcontrolS(flow uint, timeout *Time, intr bool) (int, uint)
	SbreakS(sbreak uint, timeout *Time, intr bool) (int, uint)
	DtrS(dtr uint, timeout *Time, intr bool) (int, uint)
	RtsS(rts uint, timeout *Time, intr bool) (int, uint)
	CtsS(cts uint, timeout *Time, intr bool) (int, uint)
	Dcd_dsrS(dcd_dsr uint, timeout *Time, intr bool) (int, uint)
	RiS(ri uint, timeout *Time, intr bool) (int, uint)

	// Server side only, for reporting changes to the client
	FlowState(state bool)
	Modemstate(state uint)
	Linestate(state uint)
}

// Callback events for a Gensio.
type Event interface {
	// Read data is ready on the Gensio.  err will be non-zero if
	// an error has occurred, in this case the data and auxdata is
	// ignored an you should return 0.  Otherwise data is passed
	// in.  auxdata depends on the specific gensio, see the
	// gensio.5 main page for details.  You should return the
	// number of bytes that you actually process.  Note that if
	// you do not disable read event, if you are passed an error
	// or return less than the number of bytes you processed, this
	// will be called immedately.
	Read(err int, data []byte, auxdata []string) uint64

	// Called when data can be written on the Gensio.
	WriteReady()

	// Called when a new channel is created by the remote end on a
	// channel-oriented Gensio.
	NewChannel(new_chan Gensio, auxdata []string) int

	// Called when a break is sent from the remote end on a telnet
	// connection.
	SendBreak()

	// Authorization has begun on the gensio, only called for
	// server-side gensios.  See the gensio_event.3 for details.
	AuthBegin() int

	// Certificate verification is about to start on the gensio.
	// This is primarily to set any information required to verify
	// a certificate, like the CA.  See the gensio_event.3 for
	// details.
	PrecertVerify() int

	// Certificate verification has finished on the gensio.  If
	// the certificate was valid, error will be zero and string
	// will be empty.  Otherwise an error is given.  Note that
	// errstr is *not* a gensio error, it is information from the
	// validation process.  See the gensio_event.3 for details.
	PostcertVerify(err int, errstr string) int

	// The gensio is requesting tha the given password be
	// verified.  See the gensio_event.3 for details.
	PasswordVerify(val string) int

	// The other end of a connection has requested a password.
	// You should return the proper return value and a string with
	// the password, which may not exceed maxlen bytes.  See the
	// gensio_event.3 for details.
	RequestPassword(maxlen uint64) (int, string)

	// The gensio is requesting tha the given 2-factor
	// authentication data be verified.  See the gensio_event.3
	// for details.
	Verify2fa(val []byte) int

	// The other end of a connection has requested a 2-factor
	// authentication.  You should return the proper return value
	// and a data for the authentication token.  See the
	// gensio_event.3 for details.
	Request2fa() (int, []byte)

	// An event in the user event range, this will only happen for
	// custom gensios.
	UserEvent(event int, err int, userdata *[]byte,
		  auxdata []string) int

	// Internal methods, don't mess with these.
	getEventBase() *EventBase
}

// This type must be the first entry in your event-handling callback
// object; it allows the event handler to be passed NewGensio() or
// whatnot.
type EventBase struct {
	Event

	e *raweventBase
}

// Serial callback events for a SerialGensio.  See the
// sergensio_event.3 man page for details.
type SerialEvent interface {
	Event
	Modemstate(state uint)
	Linestate(state uint)
	Signature(data []byte)
	FlowState(state bool)
	Sync()
	Baud(baud uint)
	Datasize(size uint)
	Parity(par uint)
	Stopbits(bits uint)
	Flowcontrol(flow uint)
	Iflowcontrol(flow uint)
	Sbreak(sbreak uint)
	Dtr(dtr uint)
	Rts(rts uint)
	Flush(val uint)

	// Internal methods, don't mess with these.
	getSerialEventBase() *SerialEventBase
}

// This type must be the first entry in your event-handling callback
// object; it allows the event handler to be passed NewGensio() or
// whatnot.
type SerialEventBase struct {
	EventBase

	se *rawserialEventBase
}

// Interface for handling an Open() operation completing.
type GensioOpenDone interface {
	OpenDone(err int)

	// Internal, do not use
	getGensioOpenDoneBase() *GensioOpenDoneBase
}

// This type must be the first entry in your event-handling callback
// for an Open() operation.
type GensioOpenDoneBase struct {
	GensioOpenDone

	od *rawGensioOpenDoneBase
}

// Interface for handling a Close() operation completing.
type GensioCloseDone interface {
	CloseDone()

	// Internal, do not use
	getGensioCloseDoneBase() *GensioCloseDoneBase
}

// This type must be the first entry in your event-handling callback
// for a Close() operation.
type GensioCloseDoneBase struct {
	GensioCloseDone

	cd *rawGensioCloseDoneBase
}

// Interface for handling asynchronous serial requests.
type SerialOpDone interface {
	SerOpDone(err int, val uint)

	// Internal, do not use
	getGensioSerialOpDoneBase() *SerialOpDoneBase
}

// This type must be the first entry in your event-handling callback
// for a serial operation.
type SerialOpDoneBase struct {
	SerialOpDone

	od *rawSerialOpDoneBase
}

// Interface for handling asynchronous serial signature requests.
type SerialOpSigDone interface {
	SerOpSigDone(err int, sig []byte)

	// Internal, do not use
	getGensioSerialOpSigDoneBase() *SerialOpSigDoneBase
}

// This type must be the first entry in your event-handling callback
// for a serial signature operation.
type SerialOpSigDoneBase struct {
	SerialOpSigDone

	od *rawSerialOpSigDoneBase
}

// Allocate a new Gensio.  See the str_to_gensio.3 man page for
// details.  Note that you may pass in a nil cb, but the program will
// crash if an event comes in.
func NewGensio(str string, o *OsFuncs, cb Event) Gensio {
	if cb == nil {
		rawg := Rawgensio_alloc(str, o)
		return allocGensioObj(rawg, nil)
	} else {
		rawcb := setupEvent(cb)
		rawg := Rawgensio_alloc(str, o, rawcb)
		return allocGensioObj(rawg, rawcb)
	}
}

// Like NewGensio, but allocate the Gensio on top of the given child
// Gensio in a stack.
func NewGensioChild(child Gensio, str string, o *OsFuncs,
		      cb Event) Gensio {
	var rawcb RawEvent
	if cb == nil {
		rawcb = nil
	} else {
		rawcb = setupEvent(cb)
	}
	rawg := Rawgensio_alloc(child.getRawGensio(), str, o, rawcb)
	return allocGensioObj(rawg, rawcb)
}

// An event handler for events from an Accepter
type AccepterEvent interface {
	// A new connection has come in on the Accepter.
	NewConnection(g Gensio)

	// Something went wrong in the accepter processing that could
	// not be returned as an error.
	Log(level int, log string)

	// The following are just like the ones in the Event
	// interface, except they are passed a "dummy" gensio object.
	// You can use this object to fetch authentication information
	// that you need, but you *must not* keep it around or do
	// anything else but authentication Control() fetches to get
	// the data you need.

	AuthBegin(g Gensio) int
	PrecertVerify(g Gensio) int
	PostcertVerify(g Gensio, err int, errstr string) int
	PasswordVerify(g Gensio, val string) int
	RequestPassword(g Gensio, maxlen uint64) (int, string)
	Verify2fa(g Gensio, val []byte) int
	Request2fa(g Gensio) (int, []byte)

	// Internal methods, don't mess with these.
	getAccepterEventBase() *AccepterEventBase
}

// This type must be the first entry in your event-handling callback
// for an Accepter event handler.
type AccepterEventBase struct {
	AccepterEvent

	e *rawAccepterEventBase
}

// Interface for handling a Shutdown() operation completing.
type AccepterShutdownDone interface {
	AccShutdownDone()

	// Internal, do not use
	getAccepterShutdownDoneBase() *AccepterShutdownDoneBase
}

// This type must be the first entry in your event-handling callback
// for a Shutdown() operation.
type AccepterShutdownDoneBase struct {
	AccepterShutdownDone

	od *rawAccepterShutdownDoneBase
}

// Interface for handling an Enable() operation completing.
type AccepterEnableDone interface {
	AccEnableDone()

	// Internal, do not use
	getAccepterEnableDoneBase() *AccepterEnableDoneBase
}

// This type must be the first entry in your event-handling callback
// for an Enable() operation.
type AccepterEnableDoneBase struct {
	AccepterEnableDone

	od *rawAccepterEnableDoneBase
}

// The Accepter object, used to receive connections.
type Accepter interface {
	// Start receiving connections on an Accepter.
	Startup()

	// Shut down a connector's operation.  If done is not nil, the
	// AccShutdownDone() method on the given object will be
	// called when the shutdown completes.
	Shutdown(done AccepterShutdownDone)

	// Like Shutdown(), but wait until the shutdown is complete
	// before returning.
	ShutdownS()

	// Enable/disable receiving new connections on the Accepter.
	// If done is not nil, the AccEnableDone() method on the given
	// object will be called when the enable/disable operation
	// completes
	SetCallbackEnable(val bool, done AccepterEnableDone)

	// Like SetCallbackEnable, but this will wait until the
	// operation completes before returning.
	SetCallbackEnableS(val bool)

	// Control operations.  See the gensio_acc_control.3 man page
	// for details.  See the Control() method on Gensio for
	// details on how this works.
	Control(depth int, get bool, option uint, data []byte) (int, []byte,
		uint64)

	// Turn on synchronous operation on the gensio.  See the
	// gensio_acc_set_sync.3 man page for details.
	SetSync()

	// Do an asynchronous accept on a gensio.  See the
	// gensio_acc_set_sync.3 man page for details.  If timeout is
	// not nil, wait at most the given time for the operation to
	// complete.  If intr is true, return if the thread receives a
	// signal.  This returns 0 in the first return value if a
	// gensio is accepted and returned in the second return value.
	// Othersize the first return value will be GE_TIMEDOUT if the
	// operation timed out or GE_INTERRUPTED if a signal was
	// received.
	AcceptS(timeout *Time, intr bool) (int, Gensio)

	// Create a gensio.  This is primarily for UDP; it will create
	// a connection to the remote end coming from the UDP socket.
	// See the gensio_acc_str_to_gensio.3 man page for details.
	StrToGensio(str string, cb Event) Gensio

	// Return a string type for an Accepter.  depth is the number of
	// accepters to go down in the stack to fetch the type for.  For
	// instance, if you have an accepter
	// "telnet,ssl,tcp,1234", depth 0 is "telnet", depth
	// 1 is "ssl", and depth 2 is "tcp".  This will return an
	// empty string if the depth is larger than the gensio stack.
	GetType(depth uint) string

	// Returns if gensios from this accepter are reliable (won't
	// lose data) or not.
	IsReliable() bool

	// Returns if gensios from this accepter are packet.
	IsPacket() bool

	// Returns if gensios from this accepter are message-oriented.
	IsMessage() bool

	// Return the "port" for this Accepter.  What this is depends
	// on the particular Accepter.  For TCP one, it will be the
	// port number.  See the gensio.5 man page for details.
	GetPort() string

	getRawAccepter() RawAccepter
}

// Allocate a new Accepter.  See the str_to_gensio_accepter.3 man page
// for details.  Note that you may pass in a nil cb, but the program
// will crash if an event comes in.
func NewAccepter(str string, o *OsFuncs, cb AccepterEvent) Accepter {
	if cb == nil {
		Rawa := Rawgensio_acc_alloc(str, o.RawOs_Funcs)
		return allocaccepterObj(Rawa, nil)
	} else {
		Rawa := Rawgensio_acc_alloc(str, o.RawOs_Funcs,
			setupAccepterEvent(cb))
		return allocaccepterObj(Rawa, cb)
	}
}

// Like NewAccepter, but allocate the Accepter on top of the given child
// Accepter in a stack.
func NewAccepterChild(child Accepter, str string, o *OsFuncs,
	cb AccepterEvent) Accepter {
	if cb == nil {
		rawg := Rawgensio_acc_alloc(child.getRawAccepter(), str,
			o.RawOs_Funcs, nil)
		return allocaccepterObj(rawg, nil)
	} else {
		rawg := Rawgensio_acc_alloc(child.getRawAccepter(), str,
			o.RawOs_Funcs, setupAccepterEvent(cb))
		return allocaccepterObj(rawg, cb)
	}
}

// Type used for waiting for things to complete.  Note that this has a
// Wake() function to send a wakeup, and a
// Wait(nrwakes uint, timeout *Time) to wait for the given number of
// wakeups.
type Waiter struct {
	o *OsFuncs
	RawWaiter
}

// Allocate a new Waiter object.
func NewWaiter(o *OsFuncs) *Waiter {
	w := &Waiter{o, NewRawWaiter(o)}
	runtime.SetFinalizer(w, destroyer.destroy)
	return w
}


// Interface for handling an MDNS Free() operation completing.
type MDNSFreeDone interface {
	MDNSFreeDone()

	// Internal, do not use
	getMDNSFreeDoneBase() *MDNSFreeDoneBase
}

// This type must be the first entry in your event-handling callback
// for an MDNS Free() operation.
type MDNSFreeDoneBase struct {
	MDNSFreeDone

	od *rawMDNSFreeDoneBase
}

// Interface for handling an MDNS Watch Free() operation completing.
type MDNSWatchFreeDone interface {
	MDNSWatchFreeDone()

	// Internal, do not use
	getMDNSWatchFreeDoneBase() *MDNSWatchFreeDoneBase
}

// This type must be the first entry in your event-handling callback
// for an MDNS Watch Free() operation.
type MDNSWatchFreeDoneBase struct {
	MDNSWatchFreeDone

	od *rawMDNSWatchFreeDoneBase
}

// state values for the Event callback below.  I couldn't find an easy
// way to make SWIG include these.
var MDNS_NEW_DATA int = int(GENSIO_MDNS_NEW_DATA)
var MDNS_DATA_GONE int = int(GENSIO_MDNS_DATA_GONE)
var MDNS_ALL_FOR_NOW int = int(GENSIO_MDNS_ALL_FOR_NOW)

// An event handler for MDNS Watch events.  See the gensio_mdns.3 man
// page for details.
type MDNSWatchEvent interface {
	Event(state int, interfacenum int, ipdomain int, name string,
		mtype string, domain string, host string, addr Addr,
		txt []string)

	// Internal, do not use
	getMDNSWatchEventBase() *MDNSWatchEventBase
}

// This type must be the first entry in your event-handling callback
// for an MDNS event handler.
type MDNSWatchEventBase struct {
	MDNSWatchEvent

	od *rawMDNSWatchEventBase
}

// An MDNS object, see gensio_mdns.3 for details.
type MDNS interface {
	// This is really:
	// AddService(interfacenum int, ipdomain int, name string,
	//	mtype string, domain string, host string, port int,
	//	txt []string)
	AddService(interfacenum int, ipdomain int, a ...interface{}) MDNSService

	// This is really:
	// AddWatch(interfacenum int, ipdomain int, name string,
	//	mtype string, domain string, host string,
	//		txt []string, evh MDNSWatchEvent) MDNSWatch
	AddWatch(interfacenum int, ipdomain int, a ...interface{}) MDNSWatch

	// Free the MDNS.  When the free completes (and all watches
	// and services associated with the MDNS are also freed), if
	// fh is not nil, call the MDNSFreeDone() method on fh.
	Free(fh MDNSFreeDone)
}

// Allocate a new MDNS object
func NewMDNS(o *OsFuncs) MDNS {
	rawm := NewRawMDNS(o)
	m := &mDNSO{rawm}
	runtime.SetFinalizer(m, destroyer.destroy)
	return m
}

// An MDNS service object, allocated from AddService() in an MDNS
// object.
type MDNSService interface {
	// Free the service and stop advertising it.  No free done
	// handler is needed. there are no callbacks associated with a
	// service.
	Free()
}

// An MDNS watch object, allocated from AddWatch() in an MDNS
// object.
type MDNSWatch interface {
	// Free the MDNS watch.  When the free completes, if wfh is
	// not nil, call the MDNSWatchFreeDone() method on wfh.
	Free(wfh MDNSWatchFreeDone)
}

// Return network interface information for the system.
type NetIfs interface {
	GetNumIfs() uint
	GetName(i uint) string
	IsUp(i uint) bool
	IsLoopback(i uint) bool
	IsMulticast(i uint) bool
	GetIfIndex(i uint) uint
	GetNumAddrs(i uint) uint
	GetAddrNetbits(i uint, j uint) uint
	GetAddrFamily(i uint, j uint) uint
	GetAddrStr(i uint, j uint) string
}


///////////////////////////////////////////////////////////////////////////
// Everything below here is internals

// Log output whenever an object is GC-ed
var Debug bool

// A count of the number of objects GC-ed
var GCCount uint32 = 0

type destroyer interface {
	destroy()
}

type rawLoggerBase struct {
	Os_Funcs_Log_Handler
	subl Logger
}

func (l *LoggerBase) breakLinks() {
	l.rl.subl = nil
}

func (l *LoggerBase) destroy() {
	if Debug {
		fmt.Println("Destroy Logger")
	}
	atomic.AddUint32(&GCCount, 1)
	DeleteOs_Funcs_Log_Handler(l.rl)
}

func (e *LoggerBase) getLoggerBase() *LoggerBase {
	return e
}
func setupLogger(l Logger) Os_Funcs_Log_Handler {
	lb := l.getLoggerBase()
	lb.rl = &rawLoggerBase{}
	lb.rl.subl = l
	lb.rl.Os_Funcs_Log_Handler = NewDirectorOs_Funcs_Log_Handler(lb.rl)
	runtime.SetFinalizer(lb, destroyer.destroy)
	return lb.rl
}

func (l *rawLoggerBase) Log(level Gensio_log_levels, log string) {
	l.subl.Log(int(level), log)
}

func (l *LoggerBase) Log(level int, log string) { }

func (o *OsFuncs) destroy() {
	if Debug {
		fmt.Println("Destroy OsFuncs")
	}
	atomic.AddUint32(&GCCount, 1)
	if o.l != nil {
		o.l.breakLinks()
		o.l = nil
	}
	DeleteRawOs_Funcs(o)
}

func (gt *Time) destroy() {
	if Debug {
		fmt.Println("Destroy gensio time")
	}
	atomic.AddUint32(&GCCount, 1)
	DeleteGensio_time(gt)
}

type gensioO struct {
	g RawGensio
	e RawEvent
}

func (g *gensioO) destroy() {
	if g.g != nil {
		DeleteRawGensio(g.g)
	}
	if Debug {
		fmt.Println("Gensio destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

func (g *gensioO) getRawGensio() RawGensio {
	return g.g
}

type serialGensioO struct {
	gensioO
	sg RawSerial_Gensio
}

func (g *serialGensioO) destroy() {
	if Debug {
		fmt.Println("Serial Gensio destroy")
	}
	atomic.AddUint32(&GCCount, 1)
	if g.g != nil {
		DeleteRawGensio(g.g)
	}
	if g.sg != nil {
		DeleteRawSerial_Gensio(g.sg)
	}
}

func (g *serialGensioO) getRawSerial_Gensio() RawSerial_Gensio {
	return g.g.(RawSerial_Gensio)
}

func (sg *serialGensioO) Baud(baud uint, done SerialOpDone) {
	if done == nil {
		sg.sg.Baud(baud)
	} else {
		sg.sg.Baud(baud, setupSerialOpDone(done))
	}
}

func (sg *serialGensioO) Datasize(size uint, done SerialOpDone) {
	if done == nil {
		sg.sg.Datasize(size)
	} else {
		sg.sg.Datasize(size, setupSerialOpDone(done))
	}
}

func (sg *serialGensioO) Parity(par uint, done SerialOpDone) {
	if done == nil {
		sg.sg.Parity(par)
	} else {
		sg.sg.Parity(par, setupSerialOpDone(done))
	}
}

func (sg *serialGensioO) Stopbits(bits uint, done SerialOpDone) {
	if done == nil {
		sg.sg.Stopbits(bits)
	} else {
		sg.sg.Stopbits(bits, setupSerialOpDone(done))
	}
}

func (sg *serialGensioO) Flowcontrol(flow uint, done SerialOpDone) {
	if done == nil {
		sg.sg.Flowcontrol(flow)
	} else {
		sg.sg.Flowcontrol(flow, setupSerialOpDone(done))
	}
}

func (sg *serialGensioO) Iflowcontrol(flow uint, done SerialOpDone) {
	if done == nil {
		sg.sg.Iflowcontrol(flow)
	} else {
		sg.sg.Iflowcontrol(flow, setupSerialOpDone(done))
	}
}

func (sg *serialGensioO) Sbreak(sbreak uint, done SerialOpDone) {
	if done == nil {
		sg.sg.Sbreak(sbreak)
	} else {
		sg.sg.Sbreak(sbreak, setupSerialOpDone(done))
	}
}

func (sg *serialGensioO) Dtr(dtr uint, done SerialOpDone) {
	if done == nil {
		sg.sg.Dtr(dtr)
	} else {
		sg.sg.Dtr(dtr, setupSerialOpDone(done))
	}
}

func (sg *serialGensioO) Rts(rts uint, done SerialOpDone) {
	if done == nil {
		sg.sg.Rts(rts)
	} else {
		sg.sg.Rts(rts, setupSerialOpDone(done))
	}
}

func (sg *serialGensioO) Cts(cts uint, done SerialOpDone) {
	if done == nil {
		sg.sg.Cts(cts)
	} else {
		sg.sg.Cts(cts, setupSerialOpDone(done))
	}
}

func (sg *serialGensioO) Dcd_dsr(dcd_dsr uint, done SerialOpDone) {
	if done == nil {
		sg.sg.Dcd_dsr(dcd_dsr)
	} else {
		sg.sg.Dcd_dsr(dcd_dsr, setupSerialOpDone(done))
	}
}

func (sg *serialGensioO) Ri(ri uint, done SerialOpDone) {
	if done == nil {
		sg.sg.Ri(ri)
	} else {
		sg.sg.Ri(ri, setupSerialOpDone(done))
	}
}

func (sg *serialGensioO) Signature(data []byte, done SerialOpSigDone) {
	if done == nil {
		sg.sg.Signature(data)
	} else {
		sg.sg.Signature(data, setupSerialOpSigDone(done))
	}
}

func (sg *serialGensioO) BaudS(baud uint, timeout *Time, intr bool) (int, uint) {
	rv := sg.sg.Baud_s(&baud, timeout, intr)
	return rv, baud
}

func (sg *serialGensioO) DatasizeS(size uint, timeout *Time, intr bool) (int, uint) {
	rv := sg.sg.Datasize_s(&size, timeout, intr)
	return rv, size
}

func (sg *serialGensioO) ParityS(par uint, timeout *Time, intr bool) (int, uint) {
	rv := sg.sg.Parity_s(&par, timeout, intr)
	return rv, par
}

func (sg *serialGensioO) StopbitsS(bits uint, timeout *Time, intr bool) (int, uint) {
	rv := sg.sg.Stopbits_s(&bits, timeout, intr)
	return rv, bits
}

func (sg *serialGensioO) FlowcontrolS(flow uint, timeout *Time, intr bool) (int, uint) {
	rv := sg.sg.Flowcontrol_s(&flow, timeout, intr)
	return rv, flow
}

func (sg *serialGensioO) IflowcontrolS(flow uint, timeout *Time, intr bool) (int, uint) {
	rv := sg.sg.Iflowcontrol_s(&flow, timeout, intr)
	return rv, flow
}

func (sg *serialGensioO) SbreakS(sbreak uint, timeout *Time, intr bool) (int, uint) {
	rv := sg.sg.Sbreak_s(&sbreak, timeout, intr)
	return rv, sbreak
}

func (sg *serialGensioO) DtrS(dtr uint, timeout *Time, intr bool) (int, uint) {
	rv := sg.sg.Dtr_s(&dtr, timeout, intr)
	return rv, dtr
}

func (sg *serialGensioO) RtsS(rts uint, timeout *Time, intr bool) (int, uint) {
	rv := sg.sg.Rts_s(&rts, timeout, intr)
	return rv, rts
}

func (sg *serialGensioO) CtsS(cts uint, timeout *Time, intr bool) (int, uint) {
	rv := sg.sg.Cts_s(&cts, timeout, intr)
	return rv, cts
}

func (sg *serialGensioO) Dcd_dsrS(dcd_dsr uint, timeout *Time, intr bool) (int, uint) {
	rv := sg.sg.Dcd_dsr_s(&dcd_dsr, timeout, intr)
	return rv, dcd_dsr
}

func (sg *serialGensioO) RiS(ri uint, timeout *Time, intr bool) (int, uint) {
	rv := sg.sg.Ri_s(&ri, timeout, intr)
	return rv, ri
}

func (sg *serialGensioO) FlowState(state bool) {
	sg.sg.Flow_state(state)
}

func (sg *serialGensioO) Modemstate(state uint) {
	sg.sg.Modemstate(state)
}

func (sg *serialGensioO) Linestate(state uint) {
	sg.sg.Linestate(state)
}

type raweventBase struct {
	RawEvent
	sube Event
}

func (e *EventBase) getEventBase() *EventBase {
	return e
}

func (e *EventBase) NewChannel(new_channel Gensio,
				auxdata []string) int {
	return GE_NOTSUP
}

func (e *EventBase) SendBreak() { }

func (e *EventBase) AuthBegin() int {
	return GE_NOTSUP
}

func (e *EventBase) PrecertVerify() int {
	return GE_NOTSUP
}

func (e *EventBase) PostcertVerify(err int, errstr string) int {
	return GE_NOTSUP
}

func (e *EventBase) PasswordVerify(val string) int {
	return GE_NOTSUP
}

func (e *EventBase) RequestPassword(maxsize uint64) (int, string) {
	return GE_NOTSUP, ""
}

func (e *EventBase) Verify2fa(val []byte) int {
	return GE_NOTSUP
}

func (e *EventBase) Request2fa() (int, []byte) {
	return GE_NOTSUP, nil
}

func (e *EventBase) UserEvent(event int, err int,
			      userdata *[]byte, auxdata []string) int {
	return GE_NOTSUP
}

func (e *EventBase) destroy() {
	DeleteRawEvent(e.e)
	if Debug {
		fmt.Println("Event destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

func (e *raweventBase) Read(err int, data []byte, auxdata []string) uint64 {
	return e.sube.Read(err, data, auxdata)
}

func (e *raweventBase) Write_ready() {
	e.sube.WriteReady()
}

func (e *raweventBase) New_channel(new_channel RawGensio,
				   auxdata []string) int {
	g := allocGensioObj(new_channel, nil)
	return e.sube.NewChannel(g, auxdata)
}

func (e *raweventBase) Send_break() {
	e.sube.SendBreak()
}

func (e *raweventBase) Auth_begin() int {
	return e.sube.AuthBegin()
}

func (e *raweventBase) Precert_verify() int {
	return e.sube.PrecertVerify()
}

func (e *raweventBase) Postcert_verify(err int, errstr string) int {
	return e.sube.PostcertVerify(err, errstr)
}

func (e *raweventBase) Password_verify(val string) int {
	return e.sube.PasswordVerify(val)
}

func (e *raweventBase) Request_password(maxsize uint64, val *string) int {
	rv, password := e.sube.RequestPassword(maxsize)
	*val = password
	return rv
}

func (e *raweventBase) Verify_2fa(val []byte) int {
	return e.sube.Verify2fa(val)
}

func (e *raweventBase) Request_2fa(val *[]byte) int {
	rv, ival := e.sube.Request2fa()
	*val = ival
	return rv
}

func (e *raweventBase) User_event(event int, err int,
				  userdata *[]byte, auxdata []string) int {
	return e.sube.UserEvent(event, err, userdata, auxdata)
}

func (e *raweventBase) Freed() {
	// The gensio associated with this is gone, break the loop so
	// the EventBase object will be GC-ed.
	e.sube = nil
}

type rawserialEventBase struct {
	RawSerial_Event
	subse SerialEvent
}

func (e *SerialEventBase) getSerialEventBase() *SerialEventBase {
	return e
}

func (e *SerialEventBase) Modemstate(state uint) { }
func (e *SerialEventBase) Linestate(state uint) { }
func (e *SerialEventBase) Signature(data []byte) { }
func (e *SerialEventBase) FlowState(state bool) { }
func (e *SerialEventBase) Sync() { }
func (e *SerialEventBase) Baud(baud uint) { }
func (e *SerialEventBase) Datasize(size uint) { }
func (e *SerialEventBase) Parity(par uint) { }
func (e *SerialEventBase) Stopbits(bits uint) { }
func (e *SerialEventBase) Flowcontrol(flow uint) { }
func (e *SerialEventBase) Iflowcontrol(flow uint) { }
func (e *SerialEventBase) Sbreak(sbreak uint) { }
func (e *SerialEventBase) Dtr(dtr uint) { }
func (e *SerialEventBase) Rts(rts uint) { }
func (e *SerialEventBase) Flush(val uint) { }

func (e *SerialEventBase) destroy() {
	DeleteRawSerial_Event(e.se)
	if Debug {
		fmt.Println("Serial Event destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

func (e *rawserialEventBase) Read(err int, data []byte, auxdata []string) uint64 {
	return e.subse.Read(err, data, auxdata)
}

func (e *rawserialEventBase) Write_ready() {
	e.subse.WriteReady()
}

func (e *rawserialEventBase) New_channel(new_channel RawGensio,
	auxdata []string) int {
	g := allocGensioObj(new_channel, nil)
	return e.subse.NewChannel(g, auxdata)
}

func (e *rawserialEventBase) Send_break() {
	e.subse.SendBreak()
}

func (e *rawserialEventBase) Auth_begin() int {
	return e.subse.AuthBegin()
}

func (e *rawserialEventBase) Precert_verify() int {
	return e.subse.PrecertVerify()
}

func (e *rawserialEventBase) Postcert_verify(err int, errstr string) int {
	return e.subse.PostcertVerify(err, errstr)
}

func (e *rawserialEventBase) Password_verify(val string) int {
	return e.subse.PasswordVerify(val)
}

func (e *rawserialEventBase) Request_password(maxsize uint64, val *string) int {
	rv, password := e.subse.RequestPassword(maxsize)
	*val = password
	return rv
}

func (e *rawserialEventBase) Verify_2fa(val []byte) int {
	return e.subse.Verify2fa(val)
}

func (e *rawserialEventBase) Request_2fa(val *[]byte) int {
	rv, ival := e.subse.Request2fa()
	*val = ival
	return rv
}

func (e *rawserialEventBase) User_event(event int, err int,
		userdata *[]byte, auxdata []string) int {
	return e.subse.UserEvent(event, err, userdata, auxdata)
}

func (e *rawserialEventBase) Freed() {
	// The gensio associated with this is gone, break the loop so
	// the EventBase object will be GC-ed.
	e.subse = nil
}

func (e *rawserialEventBase) Modemstate(state uint) {
	e.subse.Modemstate(state)
}

func (e *rawserialEventBase) Linestate(state uint) {
	e.subse.Linestate(state)
}

func (e *rawserialEventBase) Signature(data []byte) {
	e.subse.Signature(data)
}

func (e *rawserialEventBase) Flow_state(state bool) {
	e.subse.FlowState(state)
}

func (e *rawserialEventBase) Sync() {
	e.subse.Sync()
}

func (e *rawserialEventBase) Baud(baud uint) {
	e.subse.Baud(baud)
}

func (e *rawserialEventBase) Datasize(size uint) {
	e.subse.Datasize(size)
}

func (e *rawserialEventBase) Parity(par uint) {
	e.subse.Parity(par)
}

func (e *rawserialEventBase) Stopbits(bits uint) {
	e.subse.Stopbits(bits)
}

func (e *rawserialEventBase) Flowcontrol(flow uint) {
	e.subse.Flowcontrol(flow)
}

func (e *rawserialEventBase) Iflowcontrol(flow uint) {
	e.subse.Iflowcontrol(flow)
}

func (e *rawserialEventBase) Sbreak(sbreak uint) {
	e.subse.Sbreak(sbreak)
}

func (e *rawserialEventBase) Dtr(dtr uint) {
	e.subse.Dtr(dtr)
}

func (e *rawserialEventBase) Rts(rts uint) {
	e.subse.Rts(rts)
}

func (e *rawserialEventBase) Flush(val uint) {
	e.subse.Flush(val)
}

func setupEvent(e Event) RawEvent {
	se, ok := e.(SerialEvent)
	if ok {
		eb := se.getSerialEventBase()
		eb.se = &rawserialEventBase{}
		eb.se.subse = se
		eb.se.RawSerial_Event = NewDirectorSerial_Event(eb.se)
		runtime.SetFinalizer(eb, destroyer.destroy)
		return eb.se
	} else {
		eb := e.getEventBase()
		eb.e = &raweventBase{}
		eb.e.sube = e
		eb.e.RawEvent = NewDirectorEvent(eb.e)
		runtime.SetFinalizer(eb, destroyer.destroy)
		return eb.e
	}
}

type rawGensioOpenDoneBase struct {
	RawGensio_Open_Done
	subd GensioOpenDone
}

func (od *GensioOpenDoneBase) getGensioOpenDoneBase() *GensioOpenDoneBase {
	return od
}

func (od *rawGensioOpenDoneBase) Open_done(err int) {
	od.subd.OpenDone(err)
	od.subd = nil // Break the circular reference
}

func setupGensioOpenDone(od GensioOpenDone) RawGensio_Open_Done {
	odb := od.getGensioOpenDoneBase()
	odb.od = &rawGensioOpenDoneBase{}
	odb.od.subd = od
	odb.od.RawGensio_Open_Done = NewDirectorGensio_Open_Done(odb.od)
	runtime.SetFinalizer(odb, destroyer.destroy)
	return odb.od
}

func (od *GensioOpenDoneBase) destroy() {
	DeleteRawGensio_Open_Done(od.od)
	if Debug {
		fmt.Println("Open Done destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

type rawGensioCloseDoneBase struct {
	RawGensio_Close_Done
	subd GensioCloseDone
}

func (cd *GensioCloseDoneBase) getGensioCloseDoneBase() *GensioCloseDoneBase {
	return cd
}

func (cd *rawGensioCloseDoneBase) Close_done() {
	cd.subd.CloseDone()
	cd.subd = nil // Break the circular reference
}

func setupGensioCloseDone(cd GensioCloseDone) RawGensio_Close_Done {
	cdb := cd.getGensioCloseDoneBase()
	cdb.cd = &rawGensioCloseDoneBase{}
	cdb.cd.subd = cd
	cdb.cd.RawGensio_Close_Done = NewDirectorGensio_Close_Done(cdb.cd)
	runtime.SetFinalizer(cdb, destroyer.destroy)
	return cdb.cd
}

func (cd *GensioCloseDoneBase) destroy() {
	DeleteRawGensio_Close_Done(cd.cd)
	if Debug {
		fmt.Println("Close Done destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

type rawSerialOpDoneBase struct {
	RawSerial_Op_Done
	subd SerialOpDone
}

func (od *SerialOpDoneBase) getGensioSerialOpDoneBase() *SerialOpDoneBase {
	return od
}

func (od *rawSerialOpDoneBase) Serial_op_done(err int, val uint) {
	od.subd.SerOpDone(err, val)
	od.subd = nil // Break the circular reference
}

func setupSerialOpDone(od SerialOpDone) RawSerial_Op_Done {
	odb := od.getGensioSerialOpDoneBase()
	odb.od = &rawSerialOpDoneBase{}
	odb.od.subd = od
	odb.od.RawSerial_Op_Done = NewDirectorSerial_Op_Done(odb.od)
	runtime.SetFinalizer(odb, destroyer.destroy)
	return odb.od
}

func (od *SerialOpDoneBase) destroy() {
	DeleteRawSerial_Op_Done(od.od)
	if Debug {
		fmt.Println("Serial Op Done destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

type rawSerialOpSigDoneBase struct {
	RawSerial_Op_Sig_Done
	subd SerialOpSigDone
}

func (od *SerialOpSigDoneBase) getGensioSerialOpSigDoneBase() *SerialOpSigDoneBase {
	return od
}

func (od *rawSerialOpSigDoneBase) Serial_op_sig_done(err int, sig []byte) {
	nsig := make([]byte, len(sig))
	copy(nsig, sig)
	od.subd.SerOpSigDone(err, nsig)
	od.subd = nil // Break the circular reference
}

func setupSerialOpSigDone(od SerialOpSigDone) RawSerial_Op_Sig_Done {
	odb := od.getGensioSerialOpSigDoneBase()
	odb.od = &rawSerialOpSigDoneBase{}
	odb.od.subd = od
	odb.od.RawSerial_Op_Sig_Done = NewDirectorSerial_Op_Sig_Done(odb.od)
	runtime.SetFinalizer(odb, destroyer.destroy)
	return odb.od
}

func (od *SerialOpSigDoneBase) destroy() {
	DeleteRawSerial_Op_Sig_Done(od.od)
	if Debug {
		fmt.Println("Serial Op Sig Done destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

func allocGensioObj(rawg RawGensio, cb RawEvent) Gensio {
	var g Gensio
	if rawg.Is_serial() {
		g = &serialGensioO{gensioO{rawg, cb}, rawg.To_serial_gensio()}
	} else {
		g = &gensioO{rawg, cb}
	}
	runtime.SetFinalizer(g, destroyer.destroy)
	return g
}

func (g *gensioO) Open(od GensioOpenDone) {
	g.g.Open(setupGensioOpenDone(od))
}

func (g *gensioO) OpenNochild(od GensioOpenDone) {
	g.g.Open_nochild(setupGensioOpenDone(od))
}

func (g *gensioO) OpenS() {
	g.g.Open_s()
}

func (g *gensioO) OpenNochildS() {
	g.g.Open_nochild_s()
}

func (g *gensioO) AllocChannel(args []string, cb Event) Gensio {
	var rawcb RawEvent
	if cb == nil {
		rawcb = nil
	} else {
		rawcb = setupEvent(cb)
	}
	rawg := g.g.Alloc_channel(args, rawcb)
	return allocGensioObj(rawg, rawcb)
}

func (g *gensioO) SetReadCallbackEnable(val bool) {
	g.g.Set_read_callback_enable(val)
}

func (g *gensioO) SetWriteCallbackEnable(val bool) {
	g.g.Set_write_callback_enable(val)
}

func (g *gensioO) Write(data []byte, auxdata []string) uint64 {
	return g.g.Write(data, auxdata)
}

func (g *gensioO) Close(cd GensioCloseDone) {
	if cd == nil {
		g.g.Close()
	} else {
		g.g.Close(setupGensioCloseDone(cd))
	}
}

func (g *gensioO) CloseS() {
	g.g.Close_s()
}

func (g *gensioO) GetType(depth uint) string {
	return g.g.Get_type(depth)
}

func (g *gensioO) IsClient() bool { return g.g.Is_client() }
func (g *gensioO) IsReliable() bool { return g.g.Is_reliable() }
func (g *gensioO) IsPacket() bool { return g.g.Is_packet() }
func (g *gensioO) IsAuthenticated() bool { return g.g.Is_authenticated() }
func (g *gensioO) IsEncrypted() bool { return g.g.Is_encrypted() }
func (g *gensioO) IsMessage() bool { return g.g.Is_message() }

func (g *gensioO) SetSync() { g.g.Set_sync() }
func (g *gensioO) ClearSync() { g.g.Clear_sync() }
// Read_s has some special handling, see Rawi for details.
func (g *gensioO) ReadS(data []byte, timeout *Time,
			intr bool) (int, []byte) {
	var len uint64
	rv := g.g.Read_s(data, &len, timeout, intr)
	return rv, data[:len]
}
func (g *gensioO) WriteS(data []byte, timeout *Time,
			 intr bool) (int, uint64) {
	count := uint64(0)
	rv := g.g.Write_s(&count, data, timeout, intr)
	return rv, count
}

func (g *gensioO) Control(depth int, get bool, option uint,
			 data []byte) (int, []byte, uint64) {
	var len uint64
	var actlen uint64
	rv := g.g.Control(depth, get, option, data, &len)
	actlen = len
	if actlen > uint64(cap(data)) {
		actlen = uint64(cap(data))
	}
	return rv, data[:actlen], len
}

func (g *gensioO) SetEvent(e Event) {
	// Break the link so it will GC
	if reflect.ValueOf(g.e).IsValid() {
		oldse, ok := g.e.(*rawserialEventBase)
		if ok {
			oldse.subse = nil
		} else {
			olde := g.e.(*raweventBase)
			olde.sube = nil
		}
	}
	var rawcb RawEvent
	if e == nil {
		rawcb = nil
	} else {
		rawcb = setupEvent(e)
	}
	g.e = rawcb
	g.g.Set_event_handler(rawcb)
}

type rawAccepterEventBase struct {
	RawAccepter_Event
	sube AccepterEvent
}

func (e *AccepterEventBase) getAccepterEventBase() *AccepterEventBase {
	return e
}

// The user must implement NewConnection

func (e *AccepterEventBase) Log(level int, log string) { }

func (e *AccepterEventBase) AuthBegin(g Gensio) int {
	return GE_NOTSUP
}

func (e *AccepterEventBase) PrecertVerify(g Gensio) int {
	return GE_NOTSUP
}

func (e *AccepterEventBase) PostcertVerify(g Gensio, err int, errstr string) int {
	return GE_NOTSUP
}

func (e *AccepterEventBase) PasswordVerify(g Gensio, val string) int {
	return GE_NOTSUP
}

func (e *AccepterEventBase) RequestPassword(g Gensio, maxsize uint64) (int, string) {
	return GE_NOTSUP, ""
}

func (e *AccepterEventBase) Verify2fa(g Gensio, val []byte) int {
	return GE_NOTSUP
}

func (e *AccepterEventBase) Request2fa(g Gensio) (int, []byte) {
	return GE_NOTSUP, nil
}

func (e *AccepterEventBase) destroy() {
	DeleteRawAccepter_Event(e.e)
	if Debug {
		fmt.Println("Accepter Event destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

func (e *rawAccepterEventBase) New_connection(newg RawGensio) {
	g := allocGensioObj(newg, nil)
	e.sube.NewConnection(g)
}

func (e *rawAccepterEventBase) Log(level Gensio_log_levels, log string) {
	e.sube.Log(int(level), log)
}

func (e *rawAccepterEventBase) Auth_begin(rawg RawGensio) int {
	g := &gensioO{rawg, nil}
	rv := e.sube.AuthBegin(g)
	g.g = nil
	DeleteRawGensio(rawg)
	return rv
}

func (e *rawAccepterEventBase) Precert_verify(rawg RawGensio) int {
	g := &gensioO{rawg, nil}
	rv := e.sube.PrecertVerify(g)
	g.g = nil
	DeleteRawGensio(rawg)
	return rv
}

func (e *rawAccepterEventBase) Postcert_verify(rawg RawGensio, err int,
					       errstr string) int {
	g := &gensioO{rawg, nil}
	rv := e.sube.PostcertVerify(g, err, errstr)
	g.g = nil
	DeleteRawGensio(rawg)
	return rv
}

func (e *rawAccepterEventBase) Password_verify(rawg RawGensio, val string) int {
	g := &gensioO{rawg, nil}
	rv := e.sube.PasswordVerify(g, val)
	g.g = nil
	DeleteRawGensio(rawg)
	return rv
}

func (e *rawAccepterEventBase) Request_password(rawg RawGensio,
				     maxsize uint64, val *string) int {
	g := &gensioO{rawg, nil}
	rv, password := e.sube.RequestPassword(g, maxsize)
	*val = password
	g.g = nil
	DeleteRawGensio(rawg)
	return rv
}

func (e *rawAccepterEventBase) Verify_2fa(rawg RawGensio, val []byte) int {
	g := &gensioO{rawg, nil}
	rv := e.sube.Verify2fa(g, val)
	g.g = nil
	DeleteRawGensio(rawg)
	return rv
}

func (e *rawAccepterEventBase) Request_2fa(rawg RawGensio, val *[]byte) int {
	g := &gensioO{rawg, nil}
	rv, ival := e.sube.Request2fa(g)
	*val = ival
	g.g = nil
	DeleteRawGensio(rawg)
	return rv
}

func (e *rawAccepterEventBase) Freed() {
	// The Accepter associated with this is gone, break the loop so
	// the rawAccepterEventBase object will be GC-ed.
	e.sube = nil
}

func setupAccepterEvent(e AccepterEvent) RawAccepter_Event {
	eb := e.getAccepterEventBase()
	eb.e = &rawAccepterEventBase{}
	eb.e.sube = e
	eb.e.RawAccepter_Event = NewDirectorAccepter_Event(eb.e)
	runtime.SetFinalizer(eb, destroyer.destroy)
	return eb.e
}

type rawAccepterShutdownDoneBase struct {
	RawAccepter_Shutdown_Done
	subd AccepterShutdownDone
}

func (od *AccepterShutdownDoneBase) getAccepterShutdownDoneBase() *AccepterShutdownDoneBase {
	return od
}

func (od *rawAccepterShutdownDoneBase) Shutdown_done() {
	od.subd.AccShutdownDone()
	od.subd = nil // Break the circular reference
}

func setupAccepterShutdownDone(od AccepterShutdownDone) RawAccepter_Shutdown_Done {
	odb := od.getAccepterShutdownDoneBase()
	odb.od = &rawAccepterShutdownDoneBase{}
	odb.od.subd = od
	odb.od.RawAccepter_Shutdown_Done = NewDirectorAccepter_Shutdown_Done(odb.od)
	runtime.SetFinalizer(odb, destroyer.destroy)
	return odb.od
}

func (od *AccepterShutdownDoneBase) destroy() {
	DeleteRawAccepter_Shutdown_Done(od.od)
	if Debug {
		fmt.Println("Accepter Shutdown Done destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

type rawAccepterEnableDoneBase struct {
	RawAccepter_Enable_Done
	subd AccepterEnableDone
}

func (od *AccepterEnableDoneBase) getAccepterEnableDoneBase() *AccepterEnableDoneBase {
	return od
}

func (od *rawAccepterEnableDoneBase) Enable_done() {
	od.subd.AccEnableDone()
	od.subd = nil // Break the circular reference
}

func setupAccepterEnableDone(od AccepterEnableDone) RawAccepter_Enable_Done {
	odb := od.getAccepterEnableDoneBase()
	odb.od = &rawAccepterEnableDoneBase{}
	odb.od.subd = od
	odb.od.RawAccepter_Enable_Done = NewDirectorAccepter_Enable_Done(odb.od)
	runtime.SetFinalizer(odb, destroyer.destroy)
	return odb.od
}

func (od *AccepterEnableDoneBase) destroy() {
	DeleteRawAccepter_Enable_Done(od.od)
	if Debug {
		fmt.Println("Accepter Enable Done destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

type accepterO struct {
	a RawAccepter
	e AccepterEvent
}

func (a *accepterO) destroy() {
	if a.a != nil {
		DeleteRawAccepter(a.a)
	}
	if Debug {
		fmt.Println("Accepter destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

func (a *accepterO) getRawAccepter() RawAccepter {
	return a.a
}

func allocaccepterObj(Rawa RawAccepter, cb AccepterEvent) Accepter {
	var a Accepter
	a = &accepterO{Rawa, cb}
	runtime.SetFinalizer(a, destroyer.destroy)
	return a
}

func (a *accepterO) Startup() {
	a.a.Startup()
}

func (a *accepterO) Shutdown(done AccepterShutdownDone) {
	if done == nil {
		a.a.Shutdown()
	} else {
		a.a.Shutdown(setupAccepterShutdownDone(done))
	}
}

func (a *accepterO) ShutdownS() {
	a.a.Shutdown_s()
}

func (a *accepterO) SetCallbackEnable(val bool, done AccepterEnableDone) {
	if done == nil {
		a.a.Set_callback_enable(val)
	} else {
		a.a.Set_callback_enable(val, setupAccepterEnableDone(done))
	}
}

func (a *accepterO) SetCallbackEnableS(val bool) {
	a.a.Set_callback_enable_s(val)
}

func (a *accepterO) Control(depth int, get bool, option uint, data []byte) (int,
		[]byte, uint64) {
	var len uint64
	var actlen uint64
	rv := a.a.Control(depth, get, option, data, &len)
	actlen = len
	if actlen > uint64(cap(data)) {
		actlen = uint64(cap(data))
	}
	return rv, data[:actlen], len
}

func (a *accepterO) SetSync() {
	a.a.Set_sync()
}

func (a *accepterO) AcceptS(timeout *Time, intr bool) (int, Gensio) {
	var rawg RawGensio
	var g Gensio
	rawg = nil
	g = nil
	rv := a.a.Accept_s(&rawg, timeout, intr)
	if rv == 0 {
		g = allocGensioObj(rawg, nil)
	}
	return rv, g
}

func (a *accepterO) StrToGensio(str string, cb Event) Gensio {
	var rawcb RawEvent

	if cb == nil {
		rawcb = nil
	} else {
		rawcb = setupEvent(cb)
	}
	rawg := a.a.Str_to_gensio(str, rawcb)
	return allocGensioObj(rawg, rawcb)
}

func (a *accepterO) GetType(depth uint) string {
	return a.a.Get_type(depth)
}

func (a *accepterO) IsReliable() bool {
	return a.a.Is_reliable()
}

func (a *accepterO) IsPacket() bool {
	return a.a.Is_packet()
}

func (a *accepterO) IsMessage() bool {
	return a.a.Is_message()
}

func (a *accepterO) GetPort() string {
	return a.a.Get_port()
}

func (w *Waiter) destroy() {
	if Debug {
		fmt.Println("Destroy Waiter")
	}
	atomic.AddUint32(&GCCount, 1)
	DeleteRawWaiter(w)
}

func (w *Waiter) Wait(count uint, timeout *Time) int {
	return w.RawWait(uint(count), timeout)
}

type rawMDNSFreeDoneBase struct {
	RawMDNS_Free_Done
	subd MDNSFreeDone
}

func (od *MDNSFreeDoneBase) getMDNSFreeDoneBase() *MDNSFreeDoneBase {
	return od
}

func (od *rawMDNSFreeDoneBase) Mdns_free_done() {
	od.subd.MDNSFreeDone()
	od.subd = nil // Break the circular reference
}

func setupMDNSFreeDone(od MDNSFreeDone) RawMDNS_Free_Done {
	odb := od.getMDNSFreeDoneBase()
	odb.od = &rawMDNSFreeDoneBase{}
	odb.od.subd = od
	odb.od.RawMDNS_Free_Done = NewDirectorMDNS_Free_Done(odb.od)
	runtime.SetFinalizer(odb, destroyer.destroy)
	return odb.od
}

func (od *MDNSFreeDoneBase) destroy() {
	DeleteRawMDNS_Free_Done(od.od)
	if Debug {
		fmt.Println("MDNS Free Done destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

type rawMDNSWatchFreeDoneBase struct {
	RawMDNS_Watch_Free_Done
	subd MDNSWatchFreeDone
}

func (od *MDNSWatchFreeDoneBase) getMDNSWatchFreeDoneBase() *MDNSWatchFreeDoneBase {
	return od
}

func (od *rawMDNSWatchFreeDoneBase) Mdns_watch_free_done() {
	od.subd.MDNSWatchFreeDone()
	od.subd = nil // Break the circular reference
}

func setupMDNSWatchFreeDone(od MDNSWatchFreeDone) RawMDNS_Watch_Free_Done {
	odb := od.getMDNSWatchFreeDoneBase()
	odb.od = &rawMDNSWatchFreeDoneBase{}
	odb.od.subd = od
	odb.od.RawMDNS_Watch_Free_Done = NewDirectorMDNS_Watch_Free_Done(odb.od)
	runtime.SetFinalizer(odb, destroyer.destroy)
	return odb.od
}

func (od *MDNSWatchFreeDoneBase) destroy() {
	DeleteRawMDNS_Watch_Free_Done(od.od)
	if Debug {
		fmt.Println("Watch Free Done destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

type rawMDNSWatchEventBase struct {
	RawMDNS_Watch_Event
	subd MDNSWatchEvent
}

func (od *MDNSWatchEventBase) getMDNSWatchEventBase() *MDNSWatchEventBase {
	return od
}

func (od *rawMDNSWatchEventBase) Event(state Gensio_mdns_data_state,
		interfacenum int, ipdomain int, name string,
		mtype string, domain string, host string, addr Addr,
		txt []string) {
	if od.subd == nil {
		return
	}
	od.subd.Event(int(state), interfacenum, ipdomain, name, mtype, domain,
		host, addr, txt)
}

func setupMDNSWatchEvent(od MDNSWatchEvent) RawMDNS_Watch_Event {
	odb := od.getMDNSWatchEventBase()
	odb.od = &rawMDNSWatchEventBase{}
	odb.od.subd = od
	odb.od.RawMDNS_Watch_Event = NewDirectorMDNS_Watch_Event(odb.od)
	runtime.SetFinalizer(odb, destroyer.destroy)
	return odb.od
}

func (od *MDNSWatchEventBase) destroy() {
	DeleteRawMDNS_Watch_Event(od.od)
	if Debug {
		fmt.Println("MDNS Watch Event destroy")
	}
	atomic.AddUint32(&GCCount, 1)
}

type mDNSO struct {
	rm RawMDNS
}

func (m *mDNSO) AddService(interfacenum int, ipdomain int,
		a ...interface{}) MDNSService {
	argc := len(a)
	if argc != 6 {
		panic("Warong number of parameters to AddService")
	}
	var vname string
	var vmtype string
	var vdomain string
	var vhost string
	var name *string;
	var mtype *string;
	var domain *string
	var host *string

	if a[0] == nil {
		name = nil
	} else {
		vname = a[0].(string)
		name = &vname
	}
	if a[1] == nil {
		mtype = nil
	} else {
		vmtype = a[1].(string)
		mtype = &vmtype
	}
	if a[2] == nil {
		domain = nil
	} else {
		vdomain = a[2].(string)
		domain = &vdomain
	}
	if a[3] == nil {
		host = nil
	} else {
		vhost = a[3].(string)
		host = &vhost
	}

	rs := m.rm.Add_service(interfacenum, ipdomain, name, mtype,
		domain, host, a[4].(int), a[5].([]string))
	s := &mDNSServiceO{rs}
	runtime.SetFinalizer(s, destroyer.destroy)
	return s
}

func (m *mDNSO) AddWatch(interfacenum int, ipdomain int,
		a ...interface{}) MDNSWatch {
	argc := len(a)
	if argc != 5 {
		panic("Wrong number of parameters to AddWatch")
	}
	var vname string
	var vmtype string
	var vdomain string
	var vhost string
	var name *string
	var mtype *string
	var domain *string
	var host *string

	if a[0] == nil {
		name = nil
	} else {
		vname = a[0].(string)
		name = &vname
	}
	if a[1] == nil {
		mtype = nil
	} else {
		vmtype = a[1].(string)
		mtype = &vmtype
	}
	if a[2] == nil {
		domain = nil
	} else {
		vdomain = a[2].(string)
		domain = &vdomain
	}
	if a[3] == nil {
		host = nil
	} else {
		vhost = a[3].(string)
		host = &vhost
	}

	rweh := setupMDNSWatchEvent(a[4].(MDNSWatchEvent))
	rw := m.rm.Add_watch(interfacenum, ipdomain, name, mtype,
		domain, host, rweh)
	w := &mDNSWatchO{rw, rweh}
	runtime.SetFinalizer(w, destroyer.destroy)
	return w
}

func (m *mDNSO) destroy() {
	if Debug {
		fmt.Println("MDNS destroy")
	}
	atomic.AddUint32(&GCCount, 1)
	if m.rm != nil {
		rm := m.rm
		m.rm = nil
		rm.Free(nil)
	}
}

func (m *mDNSO) Free(mfd MDNSFreeDone) {
	if m.rm == nil {
		return
	}
	rm := m.rm
	m.rm = nil
	if mfd != nil {
		rm.Free(setupMDNSFreeDone(mfd))
	} else {
		rm.Free()
	}
}

type mDNSServiceO struct {
	rs RawMDNS_Service
}

func (ms *mDNSServiceO) destroy() {
	if Debug {
		fmt.Println("MDNS Service destroy")
	}
	atomic.AddUint32(&GCCount, 1)
	if ms.rs != nil {
		rs := ms.rs
		ms.rs = nil
		DeleteRawMDNS_Service(rs)
	}
}

func (ms *mDNSServiceO) Free() {
	if ms.rs == nil {
		return
	}
	rs := ms.rs
	ms.rs = nil
	DeleteRawMDNS_Service(rs)
}

type mDNSWatchO struct {
	rw RawMDNS_Watch
	rwe RawMDNS_Watch_Event
}

func (mw *mDNSWatchO) destroy() {
	if Debug {
		fmt.Println("MDNS Watch destroy")
	}
	atomic.AddUint32(&GCCount, 1)
	if mw.rw != nil {
		rw := mw.rw
		mw.rw = nil
		rw.Free(nil)
	}
	if mw.rwe != nil {
		r := mw.rwe.(*rawMDNSWatchEventBase)
		r.subd = nil
		mw.rwe = nil
	}
}

func (mw *mDNSWatchO) Free(mwfd MDNSWatchFreeDone) {
	if mw.rw == nil {
		return
	}
	rw := mw.rw
	mw.rw = nil
	if mwfd != nil {
		rw.Free(setupMDNSWatchFreeDone(mwfd))
	} else {
		rw.Free()
	}
}

type netIfsO struct {
	n Net_Ifs
}

func NewNetIfs(o *OsFuncs) NetIfs {
	n := &netIfsO{NewNet_Ifs(o)}
	runtime.SetFinalizer(n, destroyer.destroy)
	return n;
}

func (n *netIfsO) destroy() {
	if Debug {
		fmt.Println("Destroy NetIfs")
	}
	atomic.AddUint32(&GCCount, 1)
	DeleteNet_Ifs(n.n)
}

func (n *netIfsO) GetNumIfs() uint {
	return n.n.Get_num_ifs()
}

func (n *netIfsO) GetName(i uint) string {
	return n.n.Get_name(i)
}

func (n *netIfsO) IsUp(i uint) bool {
	return n.n.Is_up(i)
}

func (n *netIfsO) IsLoopback(i uint) bool {
	return n.n.Is_loopback(i)
}

func (n *netIfsO) IsMulticast(i uint) bool {
	return n.n.Is_multicast(i)
}

func (n *netIfsO) GetIfIndex(i uint) uint {
	return n.n.Get_ifindex(i)
}

func (n *netIfsO) GetNumAddrs(i uint) uint {
	return n.n.Get_num_addrs(i)
}

func (n *netIfsO) GetAddrNetbits(i uint, j uint) uint {
	return n.n.Get_addr_netbits(i, j)
}

func (n *netIfsO) GetAddrFamily(i uint, j uint) uint {
	return n.n.Get_addr_family(i, j)
}

func (n *netIfsO) GetAddrStr(i uint, j uint) string {
	return n.n.Get_addrstr(i, j)
}
