// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"ricketyspace.net/cryptopals/lib"
)

func C31(serve bool) {
	// In-Secure Byte Compare.
	insecureCompare := func(a, b []byte) bool {
		for i := 0; i < len(a); i++ {
			if len(b) <= i {
				return false
			}
			if a[i] != b[i] {
				return false
			}
			lib.Sleep(50000000) // Sleep 50ms
		}
		return true
	}

	// HMAC HTTP Server.
	httpServer := func() {
		// Secret for HMAC
		sec := lib.StrToBytes("Rae Street")

		// Signature checkker.
		sigCheck := func(f, s string) bool {
			// Check signature.
			h := lib.HmacSha1(sec, lib.StrToBytes(f))

			if insecureCompare(h, lib.HexStrToBytes(s)) {
				return true
			}
			return false
		}

		// HTTP Handler.
		http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			// Read query.
			var f, s []string
			var ok bool
			q := r.URL.Query()
			if f, ok = q["file"]; !ok {
				w.WriteHeader(400)
				fmt.Fprintf(w, "file not specified\n")
				return
			}
			if len(f) > 1 {
				w.WriteHeader(400)
				fmt.Fprintf(w, "Cannot specify more than one file\n")
				return
			}
			if s, ok = q["signature"]; !ok {
				w.WriteHeader(400)
				fmt.Fprintf(w, "signature not specified\n")
				return
			}
			if len(s) > 1 {
				w.WriteHeader(400)
				fmt.Fprintf(w,
					"Cannot specify more than one signature\n")
				return
			}
			if !sigCheck(f[0], s[0]) {
				w.WriteHeader(500) // Signature check failed.
			}
		})

		// Start HTTP Server
		http.ListenAndServe(":9000", nil)
	}

	// Makes HTTP POST request to the server.
	makeRequest := func(f, s string) int {
		// Make HTTP request.
		q := fmt.Sprintf("file=%s&signature=%s", f, s)
		u, err := url.Parse("http://localhost:9000/test?" + q)
		if err != nil {
			fmt.Printf("url parse failed: %v\n", err)
			return 0
		}
		res, err := http.Post(u.String(), "text/plain", nil)
		if err != nil {
			fmt.Printf("http post failed: %v\n", err)
			return res.StatusCode
		}
		return res.StatusCode
	}

	// Crack signature for file "foo".
	crack := func() {
		stc := time.Now() // Start time of crack

		f := "foo"            // File
		s := make([]byte, 20) // Signature

		i := 0
		g := byte(0)    // Guess byte.
		tl := int64(50) // Time limit.
		tries := 0
		for {
			st := time.Now()
			sc := makeRequest(f, lib.BytesToHexStr(s))
			et := time.Now().Sub(st) // Elapsed time.

			if sc == 200 {
				fmt.Printf("Signature Cracked: %x"+
					" [tot. elapsed time: %v]\n",
					s, time.Now().Sub(stc))
				break
			}
			if et.Milliseconds() >= tl {
				if tries < 5 { // Try guess at least 5 times.
					tries += 1
					continue
				}
				fmt.Printf("Signature Cracked Status: %x"+
					" [tot. elapsed time: %v]\n",
					s, time.Now().Sub(stc))
				tl = et.Milliseconds() + 50
				g = 0
				i += 1
				tries = 0
			} else {
				g += 1   // Change guess.
				s[i] = g // Set guess.
			}
		}
	}

	if serve {
		httpServer()
	} else {
		crack()
	}
}

// Output:
//
// # Server:
// $ ./cryptopals -c 31 -s
// # Client:
// $ ./cryptopals -c 31
// Signature Cracked Status: 4400000000000000000000000000000000000000 [tot. elapsed time: 370.025362ms]
// Signature Cracked Status: 44ee000000000000000000000000000000000000 [tot. elapsed time: 15.370118297s]
// Signature Cracked Status: 44ee570000000000000000000000000000000000 [tot. elapsed time: 26.920301887s]
// Signature Cracked Status: 44ee574500000000000000000000000000000000 [tot. elapsed time: 40.79052969s]
// Signature Cracked Status: 44ee5745d3000000000000000000000000000000 [tot. elapsed time: 1m33.240732048s]
// Signature Cracked Status: 44ee5745d3240000000000000000000000000000 [tot. elapsed time: 1m46.200916778s]
// Signature Cracked Status: 44ee5745d324fd00000000000000000000000000 [tot. elapsed time: 3m20.301607262s]
// Signature Cracked Status: 44ee5745d324fda7000000000000000000000000 [tot. elapsed time: 4m33.312205527s]
// Signature Cracked Status: 44ee5745d324fda71e0000000000000000000000 [tot. elapsed time: 4m50.952330999s]
// Signature Cracked Status: 44ee5745d324fda71ec000000000000000000000 [tot. elapsed time: 6m38.743155826s]
// Signature Cracked Status: 44ee5745d324fda71ec0cb000000000000000000 [tot. elapsed time: 8m45.094213819s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd0000000000000000 [tot. elapsed time: 11m15.26538765s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e00000000000000 [tot. elapsed time: 12m51.226137697s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e0c000000000000 [tot. elapsed time: 13m5.626232024s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e0c620000000000 [tot. elapsed time: 14m33.976999266s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e0c621c00000000 [tot. elapsed time: 15m4.937197749s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e0c621c70000000 [tot. elapsed time: 16m58.588103335s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e0c621c70ba0000 [tot. elapsed time: 20m15.459696698s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e0c621c70bae700 [tot. elapsed time: 24m33.111719984s]
// Signature Cracked: 44ee5745d324fda71ec0cbdd7e0c621c70bae785 [tot. elapsed time: 27m7.782947967s]
