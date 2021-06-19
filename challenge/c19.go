// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C19() {
	texts := []string{
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	}

	// Utility functions.
	cipherStreamByteGroups := func(ciphers [][]byte) map[int][]byte {
		kbg := make(map[int][]byte, 0)
		for i := 0; i < len(ciphers); i++ {
			for j := 0; j < len(ciphers[i]); j++ {
				if _, ok := kbg[j]; !ok {
					kbg[j] = make([]byte, 0)
				}
				kbg[j] = append(kbg[j], ciphers[i][j])
			}
		}
		return kbg
	}
	crackOutputBlockByteForGroup := func(pos int, g []byte) byte {
		po := make([][]byte, len(g)) // Potential Output block bytes
		for i, c := range g {
			po[i] = make([]byte, 0)
			for _, a := range lib.PrintableAscii {
				o := c ^ a
				po[i] = append(po[i], o)

				// Also try the uppercase version of ascii
				// character if it exists.
				au := lib.ByteToUpper(a)
				if a != au {
					o := c ^ au
					po[i] = append(po[i], o)
				}
			}
		}
		co := lib.BytesInCommon(po) // Common Output Block bytes.
		if len(co) < 1 {
			return 0 // NUL
		}
		if len(co) == 1 {
			return co[0]
		}
		tob := byte(0) // The Output Block byte.
		bscr := 0      // Best score.
		for _, o := range co {
			scr := 0
			for _, c := range g {
				p := c ^ o
				if s, ok := lib.AsciiScores[p]; ok {
					scr += s
				}
				if pos == 0 && lib.ByteIsUpper(p) {
					scr += 1
				}
			}
			if scr > bscr {
				bscr = scr
				tob = o
			}
		}
		return tob
	}

	// Make ciphers from plain text data.
	ciphers := make([][]byte, len(texts))
	key, err := lib.RandomBytes(16)
	if err != nil {
		fmt.Printf("Error generating key %v", err)
		return
	}
	nonce := uint64(lib.RandomInt(0, 10))
	for i, b64 := range texts {
		text := lib.Base64ToBytes(b64)
		ciphers[i], err = lib.AESEncryptCTR(text, key, lib.AESGenCTRFunc(nonce))
		if err != nil {
			fmt.Printf("Error encrypting text:%d: %v", i, err)
			return
		}
	}

	// Group the cipher streams into groups by position of the cipher
	// byte in the stream.
	cbg := cipherStreamByteGroups(ciphers)

	// Try get crack and get the output block stream.
	obs := make(map[int]byte, 0) // Output Block Stream map.
	for pos, cgrp := range cbg {
		obs[pos] = crackOutputBlockByteForGroup(pos, cgrp)
	}

	// Decipher cipher using the output block stream.
	for _, cipher := range ciphers {
		for i, c := range cipher {
			p := c ^ obs[i]
			fmt.Printf("%c", p)
		}
		fmt.Printf("\n")
	}
}

// Output:
// I have met them at close of day
// Coming with vivid faces
// From counter or desk among grey
// Eighteenth-century houses.
// I have passed with a nod of the heae
// Or polite meaningless words,
// Or have lingered awhile and said
// Polite meaningless words,
// And thought before I had done
// Of a mocking tale or a gibe
// To please a companion
// Around the fire at the club,
// Being certain that they and I
// But lived where motley is worn:
// All changed, changed utterly:
// A terrible beauty is born.
// That woman's days were spent
// In ignorant good will,
// Her nights in argument
// Until her voice grew shrill.
// What voice more sweet than hers
// When young and beautiful,
// She rode to harriers?
// This man had kept a school
// And rode our winged horse.
// This other his helper and friend
// Was coming into his force;
// He might have won fame in the end,
// So sensitive his nature seemed,
// So daring and sweet his thought.
// This other man I had dreamed
// A drunken, vain-glorious lout.
// He had done most bitter wrong
// To some who are near my heart,
// Yet I number him in the song;
// He, too, has resigned his part
// In the casual comedy;
// He, too, has been changed in his tus
// Transformed utterly:
// A terrible beauty is born.

// Stuff the program did not get correctly:
//  1. On the 5th line, 'heae' -> 'head'
//  2. On the 38th line, 'tus ' -> 'turn'
