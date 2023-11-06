//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

package main

import (
	"fmt"
	"bytes"
	"github.com/cminyard/go/gensio"
	"testbase"
)

type STelnetReflEvHnd struct {
	testbase.ReflEvHnd
	gotBreak bool
	baudV uint
	sigV []byte
	datasizeV uint
	parityV uint
	stopbitsV uint
	flowcontrolV uint
	iflowcontrolV uint
	sbreakV uint
	dtrV uint
	rtsV uint
}

func (e *STelnetReflEvHnd) Signature(sig []byte) {
	if len(sig) > 0 {
		panic("Signature received on server")
	}
	e.G.Acontrol(0, gensio.GENSIO_CONTROL_SET,
		gensio.GENSIO_ACONTROL_SER_SIGNATURE,
		e.sigV, nil, nil);
}

func (e *STelnetReflEvHnd) Flush(val uint) {
	// FIXME - how to detect?
}

func (e *STelnetReflEvHnd) Sync() {
}

func (e *STelnetReflEvHnd) Baud(val uint) {
	if val != 0 {
		e.baudV = val
	}
	e.G.Acontrol(0, gensio.GENSIO_CONTROL_SET,
		gensio.GENSIO_ACONTROL_SER_BAUD,
		[]byte(fmt.Sprint(e.baudV)), nil, nil);
}

func (e *STelnetReflEvHnd) Datasize(val uint) {
	if val != 0 {
		e.datasizeV = val
	}
	e.G.Acontrol(0, gensio.GENSIO_CONTROL_SET,
		gensio.GENSIO_ACONTROL_SER_DATASIZE,
		[]byte(fmt.Sprint(e.datasizeV)), nil, nil);
}

func (e *STelnetReflEvHnd) Parity(val uint) {
	if val != 0 {
		e.parityV = val
	}
	spar := gensio.Gensio_parity_to_str(e.parityV)
	e.G.Acontrol(0, gensio.GENSIO_CONTROL_SET,
		gensio.GENSIO_ACONTROL_SER_PARITY,
		[]byte(spar), nil, nil);
}

func (e *STelnetReflEvHnd) Stopbits(val uint) {
	if val != 0 {
		e.stopbitsV = val
	}
	e.G.Acontrol(0, gensio.GENSIO_CONTROL_SET,
		gensio.GENSIO_ACONTROL_SER_STOPBITS,
		[]byte(fmt.Sprint(e.stopbitsV)), nil, nil);
}

func (e *STelnetReflEvHnd) Flowcontrol(val uint) {
	if val != 0 {
		e.flowcontrolV = val
	}
	sflow := gensio.Gensio_flowcontrol_to_str(e.flowcontrolV)
	e.G.Acontrol(0, gensio.GENSIO_CONTROL_SET,
		gensio.GENSIO_ACONTROL_SER_FLOWCONTROL,
		[]byte(sflow), nil, nil);
}

func (e *STelnetReflEvHnd) Iflowcontrol(val uint) {
	if val != 0 {
		e.iflowcontrolV = val
	}
	sflow := gensio.Gensio_flowcontrol_to_str(e.iflowcontrolV)
	e.G.Acontrol(0, gensio.GENSIO_CONTROL_SET,
		gensio.GENSIO_ACONTROL_SER_IFLOWCONTROL,
		[]byte(sflow), nil, nil);
}

func (e *STelnetReflEvHnd) Sbreak(val uint) {
	if val != 0 {
		e.sbreakV = val
	}
	sval := gensio.Gensio_onoff_to_str(e.sbreakV)
	e.G.Acontrol(0, gensio.GENSIO_CONTROL_SET,
		gensio.GENSIO_ACONTROL_SER_SBREAK,
		[]byte(sval), nil, nil);
}

func (e *STelnetReflEvHnd) Dtr(val uint) {
	if val != 0 {
		e.dtrV = val
	}
	sval := gensio.Gensio_onoff_to_str(e.dtrV)
	e.G.Acontrol(0, gensio.GENSIO_CONTROL_SET,
		gensio.GENSIO_ACONTROL_SER_DTR,
		[]byte(sval), nil, nil);
}

func (e *STelnetReflEvHnd) Rts(val uint) {
	if val != 0 {
		e.rtsV = val
	}
	sval := gensio.Gensio_onoff_to_str(e.rtsV)
	e.G.Acontrol(0, gensio.GENSIO_CONTROL_SET,
		gensio.GENSIO_ACONTROL_SER_RTS,
		[]byte(sval), nil, nil);
}

func (e *STelnetReflEvHnd) SendBreak() {
	e.gotBreak = true
}

func (e *STelnetReflEvHnd) Modemstate(state uint) {
}

func (e *STelnetReflEvHnd) ModemstateMask(state uint) {
}

func (e *STelnetReflEvHnd) Linestate(state uint) {
}

func (e *STelnetReflEvHnd) LinestateMask(state uint) {
}

func (e *STelnetReflEvHnd) FlowState(state bool) {
}

type STelnetEvHnd struct {
	testbase.EvHnd
	SG gensio.SerialGensio
	gotBreak bool
}

func (e *STelnetEvHnd) Modemstate(state uint) {
}

func (e *STelnetEvHnd) ModemstateMask(state uint) {
}

func (e *STelnetEvHnd) Linestate(state uint) {
}

func (e *STelnetEvHnd) FlowState(state bool) {
}

func (e *STelnetEvHnd) SendBreak() {
	e.gotBreak = true
	e.W.Wake()
}

type SerOpDone struct {
	gensio.SerialOpDoneBase
	err int
	val uint
	w *gensio.Waiter
}

func (d *SerOpDone) SerOpDone(err int, val uint) {
	d.err = err
	d.val = val
	d.w.Wake()
}

type SerControlDone struct {
	gensio.GensioControlDoneBase
	err int
	val []byte
	w *gensio.Waiter
}

func (d *SerControlDone) ControlDone(err int, val []byte) {
	d.err = err
	d.val = val
	d.w.Wake()
}

var seb gensio.SerialEvent

func main() {
	fmt.Println("Starting Serial Go tests")
	o := testbase.O
	gensio.SetLogMask(gensio.LOG_MASK_ALL)

	testbase.ObjCount++
	tevh := &STelnetReflEvHnd{}
	seb = tevh
	testbase.ObjCount++
	r := testbase.NewReflector(o, "telnet(rfc2217),tcp,localhost,0", tevh)
	r.Startup()
	port := r.GetPort()

	testbase.ObjCount++
	h := &STelnetEvHnd{}
	h.Setup(o)
	testbase.ObjCount++
	g := gensio.NewGensio("telnet(rfc2217),tcp,localhost," + port, o, h)
	h.SetGensio(g)
	h.SG = g.(gensio.SerialGensio)

	testbase.VerifyAccepter(r.GetAccepter(), "telnet", true, false, false)

	g.OpenS()

	testbase.VerifyGensio(g, "telnet",
		true, true, false, false, false, false)

	tstdata := []byte("Telnet Test String")
	h.SetData(tstdata)
	testbase.ObjCount++
	rv := h.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for data: " + gensio.ErrToStr(rv))
	}

	w := gensio.NewWaiter(o)

	tevh.sigV = []byte("mysig")
	testbase.ObjCount++
	osd := &SerControlDone{}
	osd.w = w
	g.Acontrol(0, gensio.GENSIO_CONTROL_SET,
		gensio.GENSIO_ACONTROL_SER_SIGNATURE, tevh.sigV, osd, nil)
	testbase.ObjCount++
	rv = w.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for signature: " + gensio.ErrToStr(rv))
	}
	if osd.err != 0 {
		panic("Error from signature: " + gensio.ErrToStr(osd.err))
	}
	if !testbase.Cmpbytes(osd.val, []byte("mysig")) {
		panic(fmt.Sprintf("Signature mismatch, expected %s got %s",
			"mysig", string(osd.val)))
	}
	osd = nil

	var val uint
	var sval uint
	var stval []byte
	var stval2 []byte

	testbase.ObjCount++
	osd = &SerControlDone{}
	osd.w = w
	stval = []byte("19200")
	g.Acontrol(0, gensio.GENSIO_CONTROL_SET,
		gensio.GENSIO_ACONTROL_SER_BAUD,
		stval, osd, nil);
	testbase.ObjCount++
	rv = w.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for baud: " + gensio.ErrToStr(rv))
	}
	if osd.err != 0 {
		panic("Error from baud: " + gensio.ErrToStr(osd.err))
	}
	if !bytes.Equal(osd.val, stval) {
		panic(fmt.Sprintf("Baud mismatch, expected %d got %d",
			sval, osd.val))
	}
	sval = 19200
	testbase.ObjCount++
	rv, stval2, _ = g.AcontrolS(0, gensio.GENSIO_CONTROL_GET,
		gensio.GENSIO_ACONTROL_SER_BAUD, []byte("00000000"),
		gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for baud: " + gensio.ErrToStr(rv))
	}
	if !bytes.Equal(stval2, stval) {
		panic(fmt.Sprintf("Baud mismatch2, expected %d got %d",
			sval, osd.val))
	}
	stval2 = nil
	stval = nil
	osd = nil

	testbase.ObjCount++
	od := &SerOpDone{}
	od.w = w
	sval = 7
	h.SG.Datasize(sval, od)
	testbase.ObjCount++
	rv = w.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for datasize: " + gensio.ErrToStr(rv))
	}
	if od.err != 0 {
		panic("Error from datasize: " + gensio.ErrToStr(od.err))
	}
	if od.val != sval {
		panic(fmt.Sprintf("Datasize mismatch, expected %d got %d",
			sval, od.val))
	}
	testbase.ObjCount++
	rv, val = h.SG.DatasizeS(0, gensio.NewTime(1, 0), false)
	if rv != 0 {
		panic("Error waiting for datasize: " + gensio.ErrToStr(rv))
	}
	if val != sval {
		panic(fmt.Sprintf("Datasize mismatch2, expected %d got %d",
			sval, od.val))
	}
	od = nil

	testbase.ObjCount++
	od = &SerOpDone{}
	od.w = w
	sval = 2
	h.SG.Parity(sval, od)
	testbase.ObjCount++
	rv = w.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for parity: " + gensio.ErrToStr(rv))
	}
	if od.err != 0 {
		panic("Error from parity: " + gensio.ErrToStr(od.err))
	}
	if od.val != sval {
		panic(fmt.Sprintf("Parity mismatch, expected %d got %d",
			sval, od.val))
	}
	testbase.ObjCount++
	rv, val = h.SG.ParityS(0, gensio.NewTime(1, 0), false)
	if rv != 0 {
		panic("Error waiting for parity: " + gensio.ErrToStr(rv))
	}
	if val != sval {
		panic(fmt.Sprintf("Parity mismatch2, expected %d got %d",
			sval, od.val))
	}
	od = nil

	testbase.ObjCount++
	od = &SerOpDone{}
	od.w = w
	sval = gensio.GENSIO_SER_PARITY_EVEN
	h.SG.Stopbits(sval, od)
	testbase.ObjCount++
	rv = w.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for stopbits: " + gensio.ErrToStr(rv))
	}
	if od.err != 0 {
		panic("Error from stopbits: " + gensio.ErrToStr(od.err))
	}
	if od.val != sval {
		panic(fmt.Sprintf("Stopbits mismatch, expected %d got %d",
			sval, od.val))
	}
	testbase.ObjCount++
	rv, val = h.SG.StopbitsS(0, gensio.NewTime(1, 0), false)
	if rv != 0 {
		panic("Error waiting for stopbits: " + gensio.ErrToStr(rv))
	}
	if val != sval {
		panic(fmt.Sprintf("Stopbits mismatch2, expected %d got %d",
			sval, od.val))
	}
	od = nil

	testbase.ObjCount++
	od = &SerOpDone{}
	od.w = w
	sval = 1
	h.SG.Stopbits(sval, od)
	testbase.ObjCount++
	rv = w.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for stopbits: " + gensio.ErrToStr(rv))
	}
	if od.err != 0 {
		panic("Error from stopbits: " + gensio.ErrToStr(od.err))
	}
	if od.val != sval {
		panic(fmt.Sprintf("Stopbits mismatch, expected %d got %d",
			sval, od.val))
	}
	testbase.ObjCount++
	rv, val = h.SG.StopbitsS(0, gensio.NewTime(1, 0), false)
	if rv != 0 {
		panic("Error waiting for stopbits: " + gensio.ErrToStr(rv))
	}
	if val != sval {
		panic(fmt.Sprintf("Stopbits mismatch2, expected %d got %d",
			sval, od.val))
	}
	od = nil

	testbase.ObjCount++
	od = &SerOpDone{}
	od.w = w
	sval = gensio.GENSIO_SER_FLOWCONTROL_RTS_CTS
	h.SG.Flowcontrol(sval, od)
	testbase.ObjCount++
	rv = w.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for flowcontrol: " + gensio.ErrToStr(rv))
	}
	if od.err != 0 {
		panic("Error from flowcontrol: " + gensio.ErrToStr(od.err))
	}
	if od.val != sval {
		panic(fmt.Sprintf("Flowcontrol mismatch, expected %d got %d",
			sval, od.val))
	}
	testbase.ObjCount++
	rv, val = h.SG.FlowcontrolS(0, gensio.NewTime(1, 0), false)
	if rv != 0 {
		panic("Error waiting for flowcontrol: " + gensio.ErrToStr(rv))
	}
	if val != sval {
		panic(fmt.Sprintf("Flowcontrol mismatch2, expected %d got %d",
			sval, od.val))
	}
	od = nil

	testbase.ObjCount++
	od = &SerOpDone{}
	od.w = w
	sval = gensio.GENSIO_SER_FLOWCONTROL_DSR
	h.SG.Iflowcontrol(sval, od)
	testbase.ObjCount++
	rv = w.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for iflowcontrol: " + gensio.ErrToStr(rv))
	}
	if od.err != 0 {
		panic("Error from iflowcontrol: " + gensio.ErrToStr(od.err))
	}
	if od.val != sval {
		panic(fmt.Sprintf("Iflowcontrol mismatch, expected %d got %d",
			sval, od.val))
	}
	testbase.ObjCount++
	rv, val = h.SG.IflowcontrolS(0, gensio.NewTime(1, 0), false)
	if rv != 0 {
		panic("Error waiting for iflowcontrol: " + gensio.ErrToStr(rv))
	}
	if val != sval {
		panic(fmt.Sprintf("Iflowcontrol mismatch2, expected %d got %d",
			sval, od.val))
	}
	od = nil

	testbase.ObjCount++
	od = &SerOpDone{}
	od.w = w
	sval = gensio.GENSIO_SER_ON
	h.SG.Sbreak(sval, od)
	testbase.ObjCount++
	rv = w.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for sbreak: " + gensio.ErrToStr(rv))
	}
	if od.err != 0 {
		panic("Error from sbreak: " + gensio.ErrToStr(od.err))
	}
	if od.val != sval {
		panic(fmt.Sprintf("Sbreak mismatch, expected %d got %d",
			sval, od.val))
	}
	testbase.ObjCount++
	rv, val = h.SG.SbreakS(0, gensio.NewTime(1, 0), false)
	if rv != 0 {
		panic("Error waiting for sbreak: " + gensio.ErrToStr(rv))
	}
	if val != sval {
		panic(fmt.Sprintf("Sbreak mismatch2, expected %d got %d",
			sval, od.val))
	}
	od = nil

	testbase.ObjCount++
	od = &SerOpDone{}
	od.w = w
	sval = gensio.GENSIO_SER_OFF
	h.SG.Rts(sval, od)
	testbase.ObjCount++
	rv = w.Wait(1, gensio.NewTime(1, 0))
	if rv != 0 {
		panic("Error waiting for rts: " + gensio.ErrToStr(rv))
	}
	if od.err != 0 {
		panic("Error from rts: " + gensio.ErrToStr(od.err))
	}
	if od.val != sval {
		panic(fmt.Sprintf("Rts mismatch, expected %d got %d",
			sval, od.val))
	}
	testbase.ObjCount++
	rv, val = h.SG.RtsS(0, gensio.NewTime(1, 0), false)
	if rv != 0 {
		panic("Error waiting for rts: " + gensio.ErrToStr(rv))
	}
	if val != sval {
		panic(fmt.Sprintf("Rts mismatch2, expected %d got %d",
			sval, od.val))
	}
	od = nil

	// No tests for cts, dcd_dsr, ri.  Those require ipmisol

	g.CloseS()
	r.CloseS()
	r.ShutdownS()
	g = nil
	r = nil
	tevh = nil
	h.SG = nil
	h = nil
	w = nil
	o = nil

	testbase.TestShutdown()
}
