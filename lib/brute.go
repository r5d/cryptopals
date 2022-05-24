// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// Average Word Length (English).
const awl float64 = 4.7

// 'hs' must be a hex encoded string.
func XORCrackSingleKey(hs string) (byte, string, float64) {
	l := len(hs) / 2

	var k byte = 0
	var ds string = ""
	var scr float64 = 100.0

	i := byte(0)
	as := []byte(HexStrToAsciiStr(hs))
	for i < 255 {
		ks := FillBytes(i, l)
		xs := FixedXORBytes(as, ks)

		s := phraseScore(string(xs))
		if s < scr {
			k = i
			ds = string(xs)
			scr = s
		}
		i += 1
	}
	return k, ds, scr
}

func phraseScore(phrase string) float64 {
	pl := len(phrase)

	// Expected number of words.
	ew := float64(pl) / awl

	// Number of words in phrase.
	ws := 0.0

	for i := 0; i < pl; i++ {
		if phrase[i] == ' ' {
			ws += 1.0
		}
	}
	ws += 1.0

	// Compute score.
	score := 1.0 - (ws / ew)
	if score < 0 {
		score *= -1
	}
	return score
}
