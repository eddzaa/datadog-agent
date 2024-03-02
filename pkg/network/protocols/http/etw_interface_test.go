// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows && npm

package http

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	//"unsafe"

	nethttp "net/http"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/windows"
)

type testDef struct {
	name         string
	site         string
	addr         string
	port         uint16
	path         string
	code         uint16
	maxpath      int64
	pathTrucated bool
	count        uint64
}

func setupTests() []testDef {

	td := []testDef{
		{
			name: "Test default site ipv4 flood",
			site: "Default Web Site",
			addr: "127.0.0.1",
			port: 80,
			path: "/",
			code: 200,
			/*
				note: you can really only do one test at this volume. Or, if you want to do more than one test,
				you need to space them out at two minute intervals.
				Since we're doing localhost, and the connections drop into TIME_WAIT when the request is complete,
				then the host runs out of usable tcp 4-tuples to use.  Don't do more than one "flood" test, or
				if it's necessary, leave a cooldown in between tests.
			*/
			count: 10000,
		},
		{
			name:  "Test default site ipv4",
			site:  "Default Web Site",
			addr:  "127.0.0.1",
			port:  80,
			path:  "/",
			code:  200,
			count: 1,
		},
		{
			name:  "Test default site ipv4 bad path",
			site:  "Default Web Site",
			addr:  "127.0.0.1",
			port:  80,
			path:  "/foo",
			code:  404,
			count: 1,
		},
		{
			name:  "Test site1 ipv4",
			site:  "TestSite1",
			addr:  "127.0.0.1",
			port:  8081,
			path:  "/",
			code:  200,
			count: 1,
		},
		{
			name:  "Test site2 ipv4",
			site:  "TestSite2",
			addr:  "127.0.0.1",
			port:  8082,
			path:  "/",
			code:  200,
			count: 1,
		},
		{
			name:  "Test default site ipv6",
			site:  "Default Web Site",
			addr:  "::1",
			port:  80,
			path:  "/",
			code:  200,
			count: 1,
		},
		{
			name:  "Test default site ipv6 bad path",
			site:  "Default Web Site",
			addr:  "::1",
			port:  80,
			path:  "/foo",
			code:  404,
			count: 1,
		},
		{
			name:  "Test site1 ipv6",
			site:  "TestSite1",
			addr:  "::1",
			port:  8081,
			path:  "/",
			code:  200,
			count: 1,
		},
		{
			name:  "Test site2 ipv6",
			site:  "TestSite2",
			addr:  "::1",
			port:  8082,
			path:  "/",
			code:  200,
			count: 1,
		},
		{
			name:    "Test path limit one short",
			site:    "Default Web Site",
			addr:    "127.0.0.1",
			port:    80,
			path:    "/eightch",
			maxpath: 10,
			code:    404,
			count:   1,
		},
		{
			name:         "Test path limit at boundary",
			site:         "Default Web Site",
			addr:         "127.0.0.1",
			port:         80,
			path:         "/ninechar",
			pathTrucated: true,
			maxpath:      10,
			code:         404,
			count:        1,
		},
		{
			name:         "Test path limit one over",
			site:         "Default Web Site",
			addr:         "127.0.0.1",
			port:         80,
			path:         "/tencharac",
			pathTrucated: true,
			maxpath:      10,
			code:         404,
			count:        1,
		},
	}
	return td
}

func executeRequestForTest(t *testing.T, etw *EtwInterface, test testDef) (*WinHttpTransaction, error) {

	var txns []WinHttpTransaction
	var ok bool

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			trans, tok := <-etw.DataChannel
			// there is spurious other traffic from other powershell/.net things going on
			// skip transactions we're sure aren't generated by this test.
			for _, tx := range trans {
				if tx.AppPool != "<<unnamed>>" {
					txns = append(txns, tx)
					ok = tok
				}
			}
			if uint64(len(txns)) >= test.count {
				break
			}
		}

	}()

	remoteAddr := netip.MustParseAddr(test.addr)
	var urlstr string
	if remoteAddr.Is4() {
		urlstr = fmt.Sprintf("http://%s:%d%s", test.addr, test.port, test.path)
	} else {
		urlstr = fmt.Sprintf("http://[%s]:%d%s", test.addr, test.port, test.path)
	}
	for i := uint64(0); i < test.count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := nethttp.Get(urlstr)
			require.NoError(t, err)
			_ = resp.Body.Close()
		}()
	}

	wg.Wait()
	assert.Equal(t, test.count, uint64(len(txns)))
	assert.Equal(t, true, ok)
	tx := txns[0]
	return &tx, nil

}

func TestEtwTransactions(t *testing.T) {
	cfg := config.New()
	cfg.EnableHTTPMonitoring = true
	cfg.EnableNativeTLSMonitoring = true

	etw, err := NewEtwInterface(cfg)
	require.NoError(t, err)
	etw.SetCapturedProtocols(true, true)

	etw.StartReadingHttpFlows()

	/*
	 * This is a bit kludgy, but we need to wait for the ETW provider to start.  Empirically, it
	 * takes "some time" for the provider to start sending messages, which leads to some raciness
	 * if we're looking for very specific messages.
	 */
	time.Sleep(10 * time.Second)
	for _, test := range setupTests() {

		t.Run(test.name, func(t *testing.T) {

			// this overrides the setting in etw_http_service.go to allow our max unrecovered connections to be
			// large enough to handle the flood
			if test.count > completedHttpTxMaxCount {
				completedHttpTxMaxCount = test.count + 1
			}
			var expectedMax uint16

			if test.maxpath == 0 {
				expectedMax = uint16(cfg.HTTPMaxRequestFragment)
				etw.SetMaxRequestBytes(uint64(cfg.HTTPMaxRequestFragment))
			} else {
				expectedMax = uint16(test.maxpath)
				etw.SetMaxRequestBytes(uint64(test.maxpath))
			}
			tx, err := executeRequestForTest(t, etw, test)
			require.NoError(t, err)

			assert.Equal(t, uint16(expectedMax), tx.Txn.MaxRequestFragment)
			tgtbuf := make([]byte, cfg.HTTPMaxRequestFragment)
			outbuf, fullpath := computePath(tgtbuf, tx.RequestFragment)
			pathAsString := string(outbuf)

			if test.pathTrucated {
				assert.Equal(t, int(test.maxpath-1), len(pathAsString))
				assert.Equal(t, test.path[:test.maxpath-1], pathAsString)
				assert.False(t, fullpath, "expecting fullpath to not be set")
			} else {
				assert.Equal(t, test.path, pathAsString, "unexpected path")
				assert.True(t, fullpath, "expecting fullpath to be set")
			}

			expectedAddr := netip.MustParseAddr(test.addr)
			var hostaddr netip.Addr

			if expectedAddr.Is4() {
				assert.Equal(t, windows.AF_INET, int(tx.Txn.Tup.Family), "unexpected address family")
				hostaddr = netip.AddrFrom4([4]byte(tx.Txn.Tup.LocalAddr[:4]))
			} else if expectedAddr.Is6() {
				assert.Equal(t, windows.AF_INET6, int(tx.Txn.Tup.Family), "unexpected address family")
				hostaddr = netip.AddrFrom16(tx.Txn.Tup.LocalAddr)
			} else {
				assert.FailNow(t, "Unexpected address family")
			}
			assert.Equal(t, expectedAddr, hostaddr)
			assert.Equal(t, int(test.code), int(tx.Txn.ResponseStatusCode), "unexpected status code")
			assert.Equal(t, test.port, tx.Txn.Tup.LocalPort, "unexpected port")
			assert.Equal(t, test.site, tx.SiteName, "unexpected site")
			assert.Equal(t, MethodGet, Method(tx.Txn.RequestMethod), "unexpected request method")
			assert.Equal(t, "DefaultAppPool", tx.AppPool, "unexpectedd App Pool")

		})

	}
	etw.Close()
}
