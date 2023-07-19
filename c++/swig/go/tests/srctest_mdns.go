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
	if state == gensio.MDNS_WATCH_ALL_FOR_NOW {
		/* Don't do a wake here, it's not reliable. */
	} else if state == gensio.MDNS_WATCH_NEW_DATA {
		we.found = true
		we.w.Wake()
	} else {
		we.watchCount++
	}
}

type ServiceEvent struct {
	gensio.MDNSServiceEventBase
}

func (se *ServiceEvent) Event(ev int, info string) {
	if ev == gensio.MDNS_SERVICE_READY {
		fmt.Printf("Service ready: %s\n", info);
	} else if ev == gensio.MDNS_SERVICE_READY_NEW_NAME {
		fmt.Printf("Service ready with new name: %s\n", info);
	} else if ev == gensio.MDNS_SERVICE_REMOVED {
		fmt.Printf("Service removed\n");
	} else {
		fmt.Printf("Error from service: %s\n", info);
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
	se := &ServiceEvent{}
	s := m.AddService(-1, gensio.GENSIO_NETTYPE_UNSPEC, "gensio2",
		"_gensio2._tcp", nil, nil, 5001, []string{"A", "B"},
	        se)
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
