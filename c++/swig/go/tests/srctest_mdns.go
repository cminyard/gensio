//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

package main

import (
	"fmt"
	"github.com/cminyard/go/gensio"
	"testbase"
)

type FreeDone struct {
	gensio.MDNSFreeDoneBase
	w *gensio.Waiter
}

func (fd *FreeDone) MDNSFreeDone() {
	fd.w.Wake()
}

type WatchFreeDone struct {
	gensio.MDNSWatchFreeDoneBase
	w *gensio.Waiter
}

func (fd *WatchFreeDone) MDNSWatchFreeDone() {
	fd.w.Wake()
}

type WatchEvent struct {
	gensio.MDNSWatchEventBase
	w *gensio.Waiter
	watchCount int
	found bool
}

func (we *WatchEvent) Event(state int, interfacenum int, ipdomain int,
		name string, mtype string, domain string, host string,
		addr gensio.Addr, txt []string) {
	if state == gensio.MDNS_ALL_FOR_NOW {
		we.w.Wake()
	} else if state == gensio.MDNS_NEW_DATA {
		we.found = true
		we.w.Wake()
	} else {
		we.watchCount++
	}
}

func main() {
	fmt.Println("Starting MDNS Go tests")

	o := testbase.O
	gensio.SetLogMask(gensio.LOG_MASK_ALL)

	testbase.ObjCount++
	waiter := gensio.NewWaiter(o)
	testbase.ObjCount++
	m := gensio.NewMDNS(o)
	testbase.ObjCount++

	we := &WatchEvent{}
	we.w = waiter
	testbase.ObjCount++
	w := m.AddWatch(-1, gensio.GENSIO_NETTYPE_UNSPEC, "=gensio2",
		"@_gensio2.*", nil, nil, we)
	testbase.ObjCount++
	s := m.AddService(-1, gensio.GENSIO_NETTYPE_UNSPEC, "gensio2",
		"_gensio2._tcp", nil, nil, 5001, []string{"A", "B"})
	testbase.ObjCount++

	rv := waiter.Wait(1, gensio.NewTime(5, 0))
	if rv != 0 {
		panic("Error waiting for watch: " + gensio.ErrToStr(rv))
	}
	if (! we.found) {
		panic("Watch data not found")
	}

	testbase.ObjCount++
	wfh := &WatchFreeDone{}
	wfh.w = waiter
	w.Free(wfh)
	testbase.ObjCount++
	rv = waiter.Wait(1, gensio.NewTime(5, 0))
	if rv != 0 {
		panic("Error waiting for watch free: " + gensio.ErrToStr(rv))
	}
	wfh = nil
	w = nil

	s.Free()
	s = nil

	testbase.ObjCount++
	fd := &FreeDone{}
	fd.w = waiter
	m.Free(fd)
	testbase.ObjCount++
	rv = waiter.Wait(1, gensio.NewTime(5, 0))
	if rv != 0 {
		panic("Error waiting for mdns free: " + gensio.ErrToStr(rv))
	}
	fd = nil
	m = nil
	we = nil

	waiter = nil
	o = nil

	testbase.TestShutdown()
}
