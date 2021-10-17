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

func C32(serve bool) {
	// In-Secure Byte Compare.
	inSecureCompare := func(a, b []byte) bool {
		for i := 0; i < len(a); i++ {
			if len(b) <= i {
				return false
			}
			if a[i] != b[i] {
				return false
			}
			lib.Sleep(500000) // Sleep 0.5ms
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

			if inSecureCompare(h, lib.HexStrToBytes(s)) {
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
		g := byte(0)           // Guess byte.
		tl := int64(50 + 1000) // Time limit.
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
			if et.Microseconds() >= tl {
				if tries < 5 { // Try guess at least 5 times.
					tries += 1
					continue
				}
				fmt.Printf("Signature Cracked Status: %x"+
					" [tot. elapsed time: %v]\n",
					s, time.Now().Sub(stc))
				tl = et.Microseconds() + 50 + 200
				g = 0
				i += 1
				tries = 0
			} else {
				g += 1   // Change guess.
				s[i] = g // Set guess.
				tries = 0
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
// $ ./cryptopals -c 32 -s
// # Client:
// $ ./cryptopals -c 32
// Signature Cracked Status: 4400000000000000000000000000000000000000 [tot. elapsed time: 126.869763ms]
// Signature Cracked Status: 44ee000000000000000000000000000000000000 [tot. elapsed time: 5.146844063s]
// Signature Cracked Status: 44ee570000000000000000000000000000000000 [tot. elapsed time: 9.026893144s]
// Signature Cracked Status: 44ee574500000000000000000000000000000000 [tot. elapsed time: 13.646937167s]
// Signature Cracked Status: 44ee5745d3000000000000000000000000000000 [tot. elapsed time: 31.367079778s]
// Signature Cracked Status: 44ee5745d3240000000000000000000000000000 [tot. elapsed time: 35.807108716s]
// Signature Cracked Status: 44ee5745d324fd00000000000000000000000000 [tot. elapsed time: 1m8.247369106s]
// Signature Cracked Status: 44ee5745d324fda7000000000000000000000000 [tot. elapsed time: 1m32.867563308s]
// Signature Cracked Status: 44ee5745d324fda71e0000000000000000000000 [tot. elapsed time: 1m38.747613348s]
// Signature Cracked Status: 44ee5745d324fda71ec000000000000000000000 [tot. elapsed time: 2m15.067906592s]
// Signature Cracked Status: 44ee5745d324fda71ec0cb000000000000000000 [tot. elapsed time: 2m57.588228069s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd0000000000000000 [tot. elapsed time: 3m49.198625184s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e00000000000000 [tot. elapsed time: 4m20.99889498s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e0c000000000000 [tot. elapsed time: 4m25.798911645s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e0c620000000000 [tot. elapsed time: 4m55.039159294s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e0c621c00000000 [tot. elapsed time: 5m5.359239694s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e0c621c70000000 [tot. elapsed time: 5m43.219684819s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e0c621c70ba0000 [tot. elapsed time: 6m49.610083935s]
// Signature Cracked Status: 44ee5745d324fda71ec0cbdd7e0c621c70bae700 [tot. elapsed time: 8m15.280753257s]
// Signature Cracked: 44ee5745d324fda71ec0cbdd7e0c621c70bae785 [tot. elapsed time: 9m6.221153561s]
