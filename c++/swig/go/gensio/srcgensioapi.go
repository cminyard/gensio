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
)

type destroyer interface {
	destroy()
}

type Logger interface {
	Log(level int, log string)

	// Internal
	getLoggerBase() *LoggerBase
}

type rawLoggerBase struct {
	Os_Funcs_Log_Handler
	subl Logger
}

type LoggerBase struct {
	Logger
	rl *rawLoggerBase
}

func (l *LoggerBase) destroy() {
	fmt.Println("Destroy Logger")
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

func LogLevelToStr(level int) string {
	return Log_level_to_str(Gensio_log_levels(level))
}

func (l *LoggerBase) Log(level int, log string) { }

// I couldn't find an easy way to make SWIG include these.
var LOG_FATAL int = int(GENSIO_LOG_FATAL)
var LOG_ERR int = int(GENSIO_LOG_ERR)
var LOG_WARNING int = int(GENSIO_LOG_WARNING)
var LOG_INFO int = int(GENSIO_LOG_INFO)
var LOG_DEBUG int = int(GENSIO_LOG_DEBUG)
var LOG_MASK_ALL int = (1 << LOG_FATAL | 1 << LOG_ERR | 1 << LOG_WARNING |
			1 << LOG_INFO | 1 << LOG_DEBUG)
func SetLogMask(mask int) { Set_log_mask(mask) }
func GetLogMask() int { return Get_log_mask() }

func ErrToStr(err int) string { return Err_to_string(err) }

type OsFuncs struct {
	RawOs_Funcs
	l Logger // Keep a ref around to avoid GC
}

func (o *OsFuncs) Log(level int, log string) {
	o.Rawlog(Gensio_log_levels(level), log)
}

func (o *OsFuncs) destroy() {
	fmt.Println("Destroy OsFuncs")
	DeleteRawOs_Funcs(o)
}

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

type Time struct {
	Gensio_time
}

func (gt *Time) destroy() {
	fmt.Println("Destroy gensio time")
	DeleteGensio_time(gt)
}

func NewTime(secs int64, nsecs int) *Time {
	gt := &Time{NewGensio_time(secs, nsecs)}
	runtime.SetFinalizer(gt, destroyer.destroy)
	return gt
}

type Gensio interface {
	Open(od GensioOpenDone)
	OpenNochild(od GensioOpenDone)
	OpenS()
	OpenNochildS()
	AllocChannel(args []string, cb Event) Gensio
	SetReadCallbackEnable(val bool)
	SetWriteCallbackEnable(val bool)
	Write(data []byte, auxdata []string) uint64
	Close(cd GensioCloseDone)
	CloseS()
	GetType(depth uint) string
	IsClient() bool
	IsReliable() bool
	IsPacket() bool
	IsAuthenticated() bool
	IsEncrypted() bool
	IsMessage() bool
	SetSync()
	ClearSync()
	ReadS(data []byte, timeout *Time, intr bool) (int, []byte)
	WriteS(data []byte, timeout *Time, intr bool) (int, uint64)
	Control(depth int, get bool, option uint, data []byte) (int, []byte)

	SetEvent(e Event)

	getRawGensio() RawGensio
}

type gensioO struct {
	g RawGensio
	e RawEvent
}

func (g *gensioO) destroy() {
	if g.g != nil {
		DeleteRawGensio(g.g)
	}
	fmt.Println("Gensio destroy")
}

func (g *gensioO) getRawGensio() RawGensio {
	return g.g
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

	// If you pass in a valid timeout, this will return GE_TIMEDOUT
	// on a timeout.  If you set intr to true, it will return
	// GE_INTERRUPTED if a signal comes in.  On all other errors
	// it raises an exception.
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

	// Server side only, for reporting changes
	FlowState(state bool)
	Modemstate(state uint)
	Linestate(state uint)
}

type serialGensioO struct {
	gensioO
	sg RawSerial_Gensio
}

func (g *serialGensioO) destroy() {
	fmt.Println("Serial Gensio destroy")
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

type Event interface {
	Read(err int, data []byte, auxdata []string) uint64
	WriteReady()
	NewChannel(new_chan Gensio, auxdata []string) int
	SendBreak()
	AuthBegin() int
	PrecertVerify() int
	PostcertVerify(err int, errstr string) int
	PasswordVerify(val string) int
	RequestPassword(maxlen uint64) (int, string)
	Verify2fa(val []byte) int
	Request2fa() (int, []byte)
	UserEvent(event int, err int, userdata *[]byte,
		  auxdata []string) int

	// Internal methods, don't mess with these.
	getEventBase() *EventBase
}

type raweventBase struct {
	RawEvent
	sube Event
}

type EventBase struct {
	Event

	e *raweventBase
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
	fmt.Println("Event destroy")
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

type rawserialEventBase struct {
	RawSerial_Event
	subse SerialEvent
}

type SerialEventBase struct {
	EventBase

	se *rawserialEventBase
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
	fmt.Println("Serial Event destroy")
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

type GensioOpenDone interface {
	OpenDone(err int)

	// Internal, do not use
	getGensioOpenDoneBase() *GensioOpenDoneBase
}

type rawGensioOpenDoneBase struct {
	RawGensio_Open_Done
	subd GensioOpenDone
}

type GensioOpenDoneBase struct {
	GensioOpenDone

	od *rawGensioOpenDoneBase
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
	fmt.Println("Open Done destroy")
}

type GensioCloseDone interface {
	CloseDone()

	// Internal, do not use
	getGensioCloseDoneBase() *GensioCloseDoneBase
}

type rawGensioCloseDoneBase struct {
	RawGensio_Close_Done
	subd GensioCloseDone
}

type GensioCloseDoneBase struct {
	GensioCloseDone

	cd *rawGensioCloseDoneBase
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
	fmt.Println("Open Done destroy")
}

type SerialOpDone interface {
	SerOpDone(err int, val uint)

	// Internal, do not use
	getGensioSerialOpDoneBase() *SerialOpDoneBase
}

type rawSerialOpDoneBase struct {
	RawSerial_Op_Done
	subd SerialOpDone
}

type SerialOpDoneBase struct {
	SerialOpDone

	od *rawSerialOpDoneBase
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
	fmt.Println("Open Done destroy")
}

type SerialOpSigDone interface {
	SerOpSigDone(err int, sig []byte)

	// Internal, do not use
	getGensioSerialOpSigDoneBase() *SerialOpSigDoneBase
}

type rawSerialOpSigDoneBase struct {
	RawSerial_Op_Sig_Done
	subd SerialOpSigDone
}

type SerialOpSigDoneBase struct {
	SerialOpSigDone

	od *rawSerialOpSigDoneBase
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
	fmt.Println("Open Done destroy")
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
			 data []byte) (int, []byte) {
	var len uint64
	rv := g.g.Control(depth, get, option, data, &len)
	return rv, data[:len]
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

type AccepterEvent interface {
	NewConnection(g Gensio)
	Log(level int, log string)
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

type rawAccepterEventBase struct {
	RawAccepter_Event
	sube AccepterEvent
}

type AccepterEventBase struct {
	AccepterEvent

	e *rawAccepterEventBase
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
	fmt.Println("Accepter Event destroy")
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

type AccepterShutdownDone interface {
	AccShutdownDone()

	// Internal, do not use
	getAccepterShutdownDoneBase() *AccepterShutdownDoneBase
}

type rawAccepterShutdownDoneBase struct {
	RawAccepter_Shutdown_Done
	subd AccepterShutdownDone
}

type AccepterShutdownDoneBase struct {
	AccepterShutdownDone

	od *rawAccepterShutdownDoneBase
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
	fmt.Println("Accepter Shutdown Done destroy")
}

type AccepterEnableDone interface {
	AccEnableDone()

	// Internal, do not use
	getAccepterEnableDoneBase() *AccepterEnableDoneBase
}

type rawAccepterEnableDoneBase struct {
	RawAccepter_Enable_Done
	subd AccepterEnableDone
}

type AccepterEnableDoneBase struct {
	AccepterEnableDone

	od *rawAccepterEnableDoneBase
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
	fmt.Println("Accepter Enable Done destroy")
}

type Accepter interface {
	Startup()
	Shutdown(done AccepterShutdownDone)
	ShutdownS()
	SetCallbackEnable(val bool, done AccepterEnableDone)
	SetCallbackEnableS(val bool)
	Control(depth int, get bool, option uint, data []byte) (int, []byte)
	SetSync()
	AcceptS(timeout *Time, intr bool) (int, Gensio)
	StrToGensio(str string, cb Event) Gensio
	GetType(depth uint) string
	IsReliable() bool
	IsPacket() bool
	IsMessage() bool
	GetPort() string

	getRawAccepter() RawAccepter
}

type accepterO struct {
	a RawAccepter
	e AccepterEvent
}

func (a *accepterO) destroy() {
	if a.a != nil {
		DeleteRawAccepter(a.a)
	}
	fmt.Println("Accepter destroy")
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

func (a *accepterO) Control(depth int, get bool, option uint, data []byte) (int, []byte) {
	var len uint64
	rv := a.a.Control(depth, get, option, data, &len)
	return rv, data[:len]
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

type Waiter struct {
	o *OsFuncs
	RawWaiter
}

func (w *Waiter) destroy() {
	fmt.Println("Destroy Waiter")
	DeleteRawWaiter(w)
}

func NewWaiter(o *OsFuncs) *Waiter {
	w := &Waiter{o, NewRawWaiter(o)}
	runtime.SetFinalizer(w, destroyer.destroy)
	return w
}

func (w *Waiter) Wait(count uint, timeout *Time) int {
	return w.RawWait(uint(count), timeout)
}

// I couldn't find an easy way to make SWIG include these.
var MDNS_NEW_DATA int = int(GENSIO_MDNS_NEW_DATA)
var MDNS_DATA_GONE int = int(GENSIO_MDNS_DATA_GONE)
var MDNS_ALL_FOR_NOW int = int(GENSIO_MDNS_ALL_FOR_NOW)

type MDNSFreeDone interface {
	MDNSFreeDone()

	// Internal, do not use
	getMDNSFreeDoneBase() *MDNSFreeDoneBase
}

type rawMDNSFreeDoneBase struct {
	RawMDNS_Free_Done
	subd MDNSFreeDone
}

type MDNSFreeDoneBase struct {
	MDNSFreeDone

	od *rawMDNSFreeDoneBase
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
	fmt.Println("MDNS Free Done destroy")
}

type MDNSWatchFreeDone interface {
	MDNSWatchFreeDone()

	// Internal, do not use
	getMDNSWatchFreeDoneBase() *MDNSWatchFreeDoneBase
}

type rawMDNSWatchFreeDoneBase struct {
	RawMDNS_Watch_Free_Done
	subd MDNSWatchFreeDone
}

type MDNSWatchFreeDoneBase struct {
	MDNSWatchFreeDone

	od *rawMDNSWatchFreeDoneBase
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
	fmt.Println("Watch Free Done destroy")
}

type MDNSWatchEvent interface {
	Event(state int, interfacenum int, ipdomain int, name string,
		mtype string, domain string, host string, addr Addr,
		txt []string)

	// Internal, do not use
	getMDNSWatchEventBase() *MDNSWatchEventBase
}

type rawMDNSWatchEventBase struct {
	RawMDNS_Watch_Event
	subd MDNSWatchEvent
}

type MDNSWatchEventBase struct {
	MDNSWatchEvent

	od *rawMDNSWatchEventBase
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
	fmt.Println("MDNS Watch Event destroy")
}

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

	Free(fh MDNSFreeDone)
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
	fmt.Println("MDNS destroy")
	if m.rm != nil {
		rm := m.rm
		m.rm = nil
		rm.Free(nil)
	}
}

func NewMDNS(o *OsFuncs) MDNS {
	rawm := NewRawMDNS(o)
	m := &mDNSO{rawm}
	runtime.SetFinalizer(m, destroyer.destroy)
	return m
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

type MDNSService interface {
	Free()
}

type mDNSServiceO struct {
	rs RawMDNS_Service
}

func (ms *mDNSServiceO) destroy() {
	fmt.Println("MDNS Service destroy")
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

type MDNSWatch interface {
	Free(MDNSWatchFreeDone)
}

type mDNSWatchO struct {
	rw RawMDNS_Watch
	rwe RawMDNS_Watch_Event
}

func (mw *mDNSWatchO) destroy() {
	fmt.Println("MDNS Watch destroy")
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
