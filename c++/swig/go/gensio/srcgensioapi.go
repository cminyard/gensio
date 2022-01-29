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

type OsFuncs struct {
	RawOs_Funcs
}
func (o *OsFuncs) destroy() {
	fmt.Println("Destroy OsFuncs")
	DeleteRawOs_Funcs(o)
}

func NewOsFuncs(sig int) *OsFuncs {
	o := &OsFuncs{NewRawOs_Funcs(sig)}
	runtime.SetFinalizer(o, destroyer.destroy)
	return o
}

type GensioTime struct {
	Gensio_time
}

func (gt *GensioTime) destroy() {
	fmt.Println("Destroy gensio time")
	DeleteGensio_time(gt)
}

func NewGensioTime(secs int64, nsecs int) *GensioTime {
	gt := &GensioTime{NewGensio_time(secs, nsecs)}
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
	Write(data []byte, auxdata []string)
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
	ReadS(data []byte, timeout *GensioTime, intr bool) (int, []byte)
	WriteS(data []byte, timeout *GensioTime, intr bool) (int, uint64)
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
	BaudS(baud *uint, timeout *GensioTime, intr bool) int
	DatasizeS(size *uint, timeout *GensioTime, intr bool) int
	ParityS(par *uint, timeout *GensioTime, intr bool) int
	StopbitsS(bits *uint, timeout *GensioTime, intr bool) int
	FlowcontrolS(flow *uint, timeout *GensioTime, intr bool) int
	IflowcontrolS(flow *uint, timeout *GensioTime, intr bool) int
	SbreakS(sbreak *uint, timeout *GensioTime, intr bool) int
	DtrS(dtr *uint, timeout *GensioTime, intr bool) int
	RtsS(rts *uint, timeout *GensioTime, intr bool) int
	CtsS(cts *uint, timeout *GensioTime, intr bool) int
	Dcd_dsrS(dcd_dsr *uint, timeout *GensioTime, intr bool) int
	RiS(ri *uint, timeout *GensioTime, intr bool) int

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
	sg.sg.Baud(baud, setupSerialOpDone(done))
}

func (sg *serialGensioO) Datasize(size uint, done SerialOpDone) {
	sg.sg.Datasize(size, setupSerialOpDone(done))
}

func (sg *serialGensioO) Parity(par uint, done SerialOpDone) {
	sg.sg.Parity(par, setupSerialOpDone(done))
}

func (sg *serialGensioO) Stopbits(bits uint, done SerialOpDone) {
	sg.sg.Stopbits(bits, setupSerialOpDone(done))
}

func (sg *serialGensioO) Flowcontrol(flow uint, done SerialOpDone) {
	sg.sg.Flowcontrol(flow, setupSerialOpDone(done))
}

func (sg *serialGensioO) Iflowcontrol(flow uint, done SerialOpDone) {
	sg.sg.Iflowcontrol(flow, setupSerialOpDone(done))
}

func (sg *serialGensioO) Sbreak(sbreak uint, done SerialOpDone) {
	sg.sg.Sbreak(sbreak, setupSerialOpDone(done))
}

func (sg *serialGensioO) Dtr(dtr uint, done SerialOpDone) {
	sg.sg.Dtr(dtr, setupSerialOpDone(done))
}

func (sg *serialGensioO) Rts(rts uint, done SerialOpDone) {
	sg.sg.Rts(rts, setupSerialOpDone(done))
}

func (sg *serialGensioO) Cts(cts uint, done SerialOpDone) {
	sg.sg.Cts(cts, setupSerialOpDone(done))
}

func (sg *serialGensioO) Dcd_dsr(dcd_dsr uint, done SerialOpDone) {
	sg.sg.Dcd_dsr(dcd_dsr, setupSerialOpDone(done))
}

func (sg *serialGensioO) Ri(ri uint, done SerialOpDone) {
	sg.sg.Ri(ri, setupSerialOpDone(done))
}

func (sg *serialGensioO) Signature(data []byte, done SerialOpSigDone) {
	sg.sg.Signature(data, setupSerialOpSigDone(done))
}

func (sg *serialGensioO) BaudS(baud *uint, timeout *GensioTime, intr bool) int {
	return sg.sg.Baud_s(baud, timeout, intr)
}

func (sg *serialGensioO) DatasizeS(size *uint, timeout *GensioTime, intr bool) int {
	return sg.sg.Datasize_s(size, timeout, intr)
}

func (sg *serialGensioO) ParityS(par *uint, timeout *GensioTime, intr bool) int {
	return sg.sg.Parity_s(par, timeout, intr)
}

func (sg *serialGensioO) StopbitsS(bits *uint, timeout *GensioTime, intr bool) int {
	return sg.sg.Stopbits_s(bits, timeout, intr)
}

func (sg *serialGensioO) FlowcontrolS(flow *uint, timeout *GensioTime, intr bool) int {
	return sg.sg.Flowcontrol_s(flow, timeout, intr)
}

func (sg *serialGensioO) IflowcontrolS(flow *uint, timeout *GensioTime, intr bool) int {
	return sg.sg.Iflowcontrol_s(flow, timeout, intr)
}

func (sg *serialGensioO) SbreakS(sbreak *uint, timeout *GensioTime, intr bool) int {
	return sg.sg.Sbreak_s(sbreak, timeout, intr)
}

func (sg *serialGensioO) DtrS(dtr *uint, timeout *GensioTime, intr bool) int {
	return sg.sg.Dtr_s(dtr, timeout, intr)
}

func (sg *serialGensioO) RtsS(rts *uint, timeout *GensioTime, intr bool) int {
	return sg.sg.Rts_s(rts, timeout, intr)
}

func (sg *serialGensioO) CtsS(cts *uint, timeout *GensioTime, intr bool) int {
	return sg.sg.Cts_s(cts, timeout, intr)
}

func (sg *serialGensioO) Dcd_dsrS(dcd_dsr *uint, timeout *GensioTime, intr bool) int {
	return sg.sg.Dcd_dsr_s(dcd_dsr, timeout, intr)
}

func (sg *serialGensioO) RiS(ri *uint, timeout *GensioTime, intr bool) int {
	return sg.sg.Ri_s(ri, timeout, intr)
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
	Send_break()
	Auth_begin() int
	Precert_verify() int
	Postcert_verify(err int, errstr string) int
	Password_verify(val string) int
	Request_password(maxlen uint64, val *string) int
	Verify_2fa(val []byte) int
	Request_2fa(val *[]byte) int
	User_event(event int, err int, userdata *[]byte,
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

func (e *EventBase) Send_break() { }

func (e *EventBase) Auth_begin() int {
	return GE_NOTSUP
}

func (e *EventBase) Precert_verify() int {
	return GE_NOTSUP
}

func (e *EventBase) Postcert_verify(err int, errstr string) int {
	return GE_NOTSUP
}

func (e *EventBase) Password_verify(val string) int {
	return GE_NOTSUP
}

func (e *EventBase) Request_password(maxsize uint64, val *string) int {
	return GE_NOTSUP
}

func (e *EventBase) Verify_2fa(val []byte) int {
	return GE_NOTSUP
}

func (e *EventBase) Request_2fa(val *[]byte) int {
	return GE_NOTSUP
}

func (e *EventBase) User_event(event int, err int,
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
	e.sube.Send_break()
}

func (e *raweventBase) Auth_begin() int {
	return e.sube.Auth_begin()
}

func (e *raweventBase) Precert_verify() int {
	return e.sube.Precert_verify()
}

func (e *raweventBase) Postcert_verify(err int, errstr string) int {
	return e.sube.Postcert_verify(err, errstr)
}

func (e *raweventBase) Password_verify(val string) int {
	return e.sube.Password_verify(val)
}

func (e *raweventBase) Request_password(maxsize uint64, val *string) int {
	return e.sube.Request_password(maxsize, val)
}

func (e *raweventBase) Verify_2fa(val []byte) int {
	return e.sube.Verify_2fa(val)
}

func (e *raweventBase) Request_2fa(val *[]byte) int {
	return e.sube.Request_2fa(val)
}

func (e *raweventBase) User_event(event int, err int,
				  userdata *[]byte, auxdata []string) int {
	return e.sube.User_event(event, err, userdata, auxdata)
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

	// Internal methods, don't mess with these.
	getSerialEventBase() *SerialEventBase
}

type rawserialEventBase struct {
	RawSerial_Event
	subse SerialEvent
}

type SerialEventBase struct {
	SerialEvent

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
	e.subse.Send_break()
}

func (e *rawserialEventBase) Auth_begin() int {
	return e.subse.Auth_begin()
}

func (e *rawserialEventBase) Precert_verify() int {
	return e.subse.Precert_verify()
}

func (e *rawserialEventBase) Postcert_verify(err int, errstr string) int {
	return e.subse.Postcert_verify(err, errstr)
}

func (e *rawserialEventBase) Password_verify(val string) int {
	return e.subse.Password_verify(val)
}

func (e *rawserialEventBase) Request_password(maxsize uint64, val *string) int {
	return e.subse.Request_password(maxsize, val)
}

func (e *rawserialEventBase) Verify_2fa(val []byte) int {
	return e.subse.Verify_2fa(val)
}

func (e *rawserialEventBase) Request_2fa(val *[]byte) int {
	return e.subse.Request_2fa(val)
}

func (e *rawserialEventBase) User_event(event int, err int,
				  userdata *[]byte, auxdata []string) int {
	return e.subse.User_event(event, err, userdata, auxdata)
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
	Open_done(err int)

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
	od.subd.Open_done(err)
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
	Close_done()

	// Internal, do not use
	getGensioOpenDoneBase() *GensioCloseDoneBase
}

type rawGensioCloseDoneBase struct {
	RawGensio_Close_Done
	subd GensioCloseDone
}

type GensioCloseDoneBase struct {
	GensioCloseDone

	cd *rawGensioCloseDoneBase
}

func (cd *GensioCloseDoneBase) getGensioOpenDoneBase() *GensioCloseDoneBase {
	return cd
}

func (cd *rawGensioCloseDoneBase) Close_done() {
	cd.subd.Close_done()
	cd.subd = nil // Break the circular reference
}

func setupGensioCloseDone(cd GensioCloseDone) RawGensio_Close_Done {
	cdb := cd.getGensioOpenDoneBase()
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
	Open_done(err int)

	// Internal, do not use
	getGensioOpenDoneBase() *SerialOpDoneBase
}

type rawSerialOpDoneBase struct {
	RawSerial_Op_Done
	subd SerialOpDone
}

type SerialOpDoneBase struct {
	SerialOpDone

	od *rawSerialOpDoneBase
}

func (od *SerialOpDoneBase) getGensioOpenDoneBase() *SerialOpDoneBase {
	return od
}

func (od *rawSerialOpDoneBase) Open_done(err int) {
	od.subd.Open_done(err)
	od.subd = nil // Break the circular reference
}

func setupSerialOpDone(od SerialOpDone) RawSerial_Op_Done {
	odb := od.getGensioOpenDoneBase()
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
	Open_done(err int)

	// Internal, do not use
	getGensioOpenDoneBase() *SerialOpSigDoneBase
}

type rawSerialOpSigDoneBase struct {
	RawSerial_Op_Sig_Done
	subd SerialOpSigDone
}

type SerialOpSigDoneBase struct {
	SerialOpSigDone

	od *rawSerialOpSigDoneBase
}

func (od *SerialOpSigDoneBase) getGensioOpenDoneBase() *SerialOpSigDoneBase {
	return od
}

func (od *rawSerialOpSigDoneBase) Open_done(err int) {
	od.subd.Open_done(err)
	od.subd = nil // Break the circular reference
}

func setupSerialOpSigDone(od SerialOpSigDone) RawSerial_Op_Sig_Done {
	odb := od.getGensioOpenDoneBase()
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

func allocGensioObj(Rawg RawGensio, cb RawEvent) Gensio {
	var g Gensio
	if Rawg.Is_serial() {
		fmt.Println("A")
		g = &serialGensioO{gensioO{Rawg, cb}, Rawg.To_serial_gensio()}
	} else {
		fmt.Println("B")
		g = &gensioO{Rawg, cb}
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
	Rawcb := setupEvent(cb)
	Rawg := g.g.Alloc_channel(args, Rawcb)
	return allocGensioObj(Rawg, Rawcb)
}

func (g *gensioO) SetReadCallbackEnable(val bool) {
	g.g.Set_read_callback_enable(val)
}

func (g *gensioO) SetWriteCallbackEnable(val bool) {
	g.g.Set_write_callback_enable(val)
}

func (g *gensioO) Write(data []byte, auxdata []string) {
	g.g.Write(data, auxdata)
}

func (g *gensioO) Close(cd GensioCloseDone) {
	g.g.Close(setupGensioCloseDone(cd))
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
func (g *gensioO) ReadS(data []byte, timeout *GensioTime,
			intr bool) (int, []byte) {
	var len uint64
	rv := g.g.Read_s(data, &len, timeout, intr)
	return rv, data[:len]
}
func (g *gensioO) WriteS(data []byte, timeout *GensioTime,
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
	Rawcb := setupEvent(e)
	g.e = Rawcb
	g.g.Set_event_handler(Rawcb)
}

func GensioAlloc(str string, o *OsFuncs, cb Event) Gensio {
	Rawcb := setupEvent(cb)
	Rawg := Rawgensio_alloc(str, o, Rawcb)
	return allocGensioObj(Rawg, Rawcb)
}

func GensioAllocChild(child Gensio, str string, o *OsFuncs,
		      cb Event) Gensio {
	Rawcb := setupEvent(cb)
	Rawg := Rawgensio_alloc(child.getRawGensio(), str, o, Rawcb)
	return allocGensioObj(Rawg, Rawcb)
}

type AccepterEvent interface {
	NewConnection(g Gensio)
	log(level int, log string)
	AuthBegin(g Gensio) int
	PrecertVerify(g Gensio) int
	PostcertVerify(g Gensio, err int, errstr string) int
	PasswordVerify(g Gensio, val string) int
	RequestPassword(g Gensio, maxlen uint64, val *string) int
	Verify2fa(g Gensio, val []byte) int
	Request2fa(g Gensio, val *[]byte) int

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

func (e *AccepterEventBase) log(level int, log string) { }

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

func (e *AccepterEventBase) RequestPassword(g Gensio,
				     maxsize uint64, val *string) int {
	return GE_NOTSUP
}

func (e *AccepterEventBase) Verify2fa(g Gensio, val []byte) int {
	return GE_NOTSUP
}

func (e *AccepterEventBase) Request2fa(g Gensio, val *[]byte) int {
	return GE_NOTSUP
}

func (e *AccepterEventBase) destroy() {
	DeleteRawAccepter_Event(e.e)
	fmt.Println("Accepter Event destroy")
}

func (e *rawAccepterEventBase) New_connection(Rawg RawGensio) {
	g := allocGensioObj(Rawg, nil)
	e.sube.NewConnection(g)
}

func (e *rawAccepterEventBase) log(level int, log string) {
	e.sube.log(level, log)
}

func (e *rawAccepterEventBase) Auth_begin(Rawg RawGensio) int {
	g := allocGensioObj(Rawg, nil)
	return e.sube.AuthBegin(g)
}

func (e *rawAccepterEventBase) Precert_verify(Rawg RawGensio) int {
	g := allocGensioObj(Rawg, nil)
	return e.sube.PrecertVerify(g)
}

func (e *rawAccepterEventBase) Postcert_verify(Rawg RawGensio, err int,
					       errstr string) int {
	g := allocGensioObj(Rawg, nil)
	return e.sube.PostcertVerify(g, err, errstr)
}

func (e *rawAccepterEventBase) Password_verify(Rawg RawGensio, val string) int {
	g := allocGensioObj(Rawg, nil)
	return e.sube.PasswordVerify(g, val)
}

func (e *rawAccepterEventBase) Request_password(Rawg RawGensio,
				     maxsize uint64, val *string,) int {
	g := allocGensioObj(Rawg, nil)
	return e.sube.RequestPassword(g, maxsize, val)
}

func (e *rawAccepterEventBase) Verify_2fa(Rawg RawGensio, val []byte) int {
	g := allocGensioObj(Rawg, nil)
	return e.sube.Verify2fa(g, val)
}

func (e *rawAccepterEventBase) Request_2fa(Rawg RawGensio,
					   val *[]byte) int {
	g := allocGensioObj(Rawg, nil)
	return e.sube.Request2fa(g, val)
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
	Open_done(err int)

	// Internal, do not use
	getGensioOpenDoneBase() *AccepterShutdownDoneBase
}

type rawAccepterShutdownDoneBase struct {
	RawAccepter_Shutdown_Done
	subd AccepterShutdownDone
}

type AccepterShutdownDoneBase struct {
	AccepterShutdownDone

	od *rawAccepterShutdownDoneBase
}

func (od *AccepterShutdownDoneBase) getGensioOpenDoneBase() *AccepterShutdownDoneBase {
	return od
}

func (od *rawAccepterShutdownDoneBase) Open_done(err int) {
	od.subd.Open_done(err)
	od.subd = nil // Break the circular reference
}

func setupAccepterShutdownDone(od AccepterShutdownDone) RawAccepter_Shutdown_Done {
	odb := od.getGensioOpenDoneBase()
	odb.od = &rawAccepterShutdownDoneBase{}
	odb.od.subd = od
	odb.od.RawAccepter_Shutdown_Done = NewDirectorAccepter_Shutdown_Done(odb.od)
	runtime.SetFinalizer(odb, destroyer.destroy)
	return odb.od
}

func (od *AccepterShutdownDoneBase) destroy() {
	DeleteRawAccepter_Shutdown_Done(od.od)
	fmt.Println("Open Done destroy")
}

type AccepterEnableDone interface {
	Open_done(err int)

	// Internal, do not use
	getGensioOpenDoneBase() *AccepterEnableDoneBase
}

type rawAccepterEnableDoneBase struct {
	RawAccepter_Enable_Done
	subd AccepterEnableDone
}

type AccepterEnableDoneBase struct {
	AccepterEnableDone

	od *rawAccepterEnableDoneBase
}

func (od *AccepterEnableDoneBase) getGensioOpenDoneBase() *AccepterEnableDoneBase {
	return od
}

func (od *rawAccepterEnableDoneBase) Open_done(err int) {
	od.subd.Open_done(err)
	od.subd = nil // Break the circular reference
}

func setupAccepterEnableDone(od AccepterEnableDone) RawAccepter_Enable_Done {
	odb := od.getGensioOpenDoneBase()
	odb.od = &rawAccepterEnableDoneBase{}
	odb.od.subd = od
	odb.od.RawAccepter_Enable_Done = NewDirectorAccepter_Enable_Done(odb.od)
	runtime.SetFinalizer(odb, destroyer.destroy)
	return odb.od
}

func (od *AccepterEnableDoneBase) destroy() {
	DeleteRawAccepter_Enable_Done(od.od)
	fmt.Println("Open Done destroy")
}

type Accepter interface {
	Startup()
	Shutdown(done AccepterShutdownDone)
	ShutdownS()
	SetCallbackEnable(val bool, done AccepterEnableDone)
	SetCallbackEnableS(val bool)
	Control(depth int, get bool, option uint, data []byte) (int, []byte)
	SetSync()
	AcceptS(timeout *GensioTime, intr bool) (int, Gensio)
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
	a.a.Shutdown(setupAccepterShutdownDone(done))
}

func (a *accepterO) ShutdownS() {
	a.a.Shutdown_s()
}

func (a *accepterO) SetCallbackEnable(val bool, done AccepterEnableDone) {
	a.a.Set_callback_enable(val, setupAccepterEnableDone(done))
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

func (a *accepterO) AcceptS(timeout *GensioTime, intr bool) (int, Gensio) {
	var Rawg RawGensio
	var g Gensio
	Rawg = nil
	g = nil
	rv := a.a.Accept_s(&Rawg, timeout, intr)
	if rv == 0 {
		g = allocGensioObj(Rawg, nil)
	}
	return rv, g
}

func (a *accepterO) StrToGensio(str string, cb Event) Gensio {
	Rawcb := setupEvent(cb)
	Rawg := a.a.Str_to_gensio(str, Rawcb)
	return allocGensioObj(Rawg, Rawcb)
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

func GensioAccAlloc(str string, o *OsFuncs, cb AccepterEvent) Accepter {
	Rawa := Rawgensio_acc_alloc(str, o, setupAccepterEvent(cb))
	return allocaccepterObj(Rawa, cb)
}

func GensioAccAllocChild(child Accepter, str string, o *OsFuncs,
			 cb AccepterEvent) Accepter {
	Rawg := Rawgensio_acc_alloc(child.getRawAccepter(), str, o,
					   setupAccepterEvent(cb))
	return allocaccepterObj(Rawg, cb)
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
