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

func main() {
	netifs := gensio.NewNetIfs(testbase.O)
	numifs := netifs.GetNumIfs()
	var i uint
	for i = 0; i < numifs; i++ {
		name := netifs.GetName(i)
		up := ""
		if netifs.IsUp(i) {
			up = " up"
		}
		loopback := ""
		if netifs.IsLoopback(i) {
			loopback = " loopback"
		}
		multicast := ""
		if netifs.IsMulticast(i) {
			multicast = " multicast"
		}
		ifidx := netifs.GetIfIndex(i)
		numaddrs := netifs.GetNumAddrs(i)
		fmt.Printf("%s(%d):%s%s%s:\n", name, ifidx,
			up, loopback, multicast)
		var j uint
		for j = 0; j < numaddrs; j++ {
			netbits := netifs.GetAddrNetbits(i, j)
			family := netifs.GetAddrFamily(i, j)
			addrstr := netifs.GetAddrStr(i, j)
			fmt.Printf("  %s/%d %d\n", addrstr, netbits, family)
		}
	}

	testbase.TestShutdown()
}
