// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C10() {
	cipher := lib.Base64ToBytes(`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`)
	var key []byte = lib.StrToBytes("YELLOW SUBMARINE")
	var iv []byte = make([]byte, 16)
	plain80038A := lib.HexStrToBytes("6bc1bee22e409f96e93d7e117393172a" +
		"ae2d8a571e03ac9c9eb76fac45af8e51" +
		"30c81c46a35ce411e5fbc1191a0a52ef" +
		"f69f2445df4f9b17ad2b417be66c3710")
	key80038A := lib.HexStrToBytes("2b7e151628aed2a6abf7158809cf4f3c")
	iv80038A := lib.HexStrToBytes("000102030405060708090a0b0c0d0e0f")
	cipher80038A := lib.AESEncryptCBC(plain80038A, key80038A, iv80038A)
	fmt.Printf("NIST SP 800-38A F.2.1 (has padding):\n%v\n",
		lib.PrettifyHexStr(lib.BytesToHexStr(cipher80038A)))
	o, _ := lib.AESDecryptCBC(cipher80038A, key80038A, iv80038A)
	fmt.Printf("NIST SP 800-38A F.2.2:\n%v\n",
		lib.PrettifyHexStr(lib.BytesToHexStr(o)))
	o, _ = lib.AESDecryptCBC(cipher, key, iv)
	fmt.Printf("Cryptopals Ch. 10:\n%v", lib.BytesToStr(o))
}

// Output:
//
// NIST SP 800-38A F.2.1 (has padding):
// 7649abac8119b246cee98e9b12e9197d
// 5086cb9b507219ee95db113a917678b2
// 73bed6b8e3c1743b7116e69e22229516
// 3ff1caa1681fac09120eca307586e1a7
// 8cb82807230e1321d3fae00d18cc2012
//
// NIST SP 800-38A F.2.2:
// 6bc1bee22e409f96e93d7e117393172a
// ae2d8a571e03ac9c9eb76fac45af8e51
// 30c81c46a35ce411e5fbc1191a0a52ef
// f69f2445df4f9b17ad2b417be66c3710
//
// Cryptopals Ch. 10:
// I'm back and I'm ringin' the bell
// A rockin' on the mike while the fly girls yell
// In ecstasy in the back of me
// Well that's my DJ Deshay cuttin' all them Z's
// Hittin' hard and the girlies goin' crazy
// Vanilla's on the mike, man I'm not lazy.
//
// I'm lettin' my drug kick in
// It controls my mouth and I begin
// To just let it flow, let my concepts go
// My posse's to the side yellin', Go Vanilla Go!
//
// Smooth 'cause that's the way I will be
// And if you don't give a damn, then
// Why you starin' at me
// So get off 'cause I control the stage
// There's no dissin' allowed
// I'm in my own phase
// The girlies sa y they love me and that is ok
// And I can dance better than any kid n' play
//
// Stage 2 -- Yea the one ya' wanna listen to
// It's off my head so let the beat play through
// So I can funk it up and make it sound good
// 1-2-3 Yo -- Knock on some wood
// For good luck, I like my rhymes atrocious
// Supercalafragilisticexpialidocious
// I'm an effect and that you can bet
// I can take a fly girl and make her wet.
//
// I'm like Samson -- Samson to Delilah
// There's no denyin', You can try to hang
// But you'll keep tryin' to get my style
// Over and over, practice makes perfect
// But not if you're a loafer.
//
// You'll get nowhere, no place, no time, no girls
// Soon -- Oh my God, homebody, you probably eat
// Spaghetti with a spoon! Come on and say it!
//
// VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino
// Intoxicating so you stagger like a wino
// So punks stop trying and girl stop cryin'
// Vanilla Ice is sellin' and you people are buyin'
// 'Cause why the freaks are jockin' like Crazy Glue
// Movin' and groovin' trying to sing along
// All through the ghetto groovin' this here song
// Now you're amazed by the VIP posse.
//
// Steppin' so hard like a German Nazi
// Startled by the bases hittin' ground
// There's no trippin' on mine, I'm just gettin' down
// Sparkamatic, I'm hangin' tight like a fanatic
// You trapped me once and I thought that
// You might have it
// So step down and lend me your ear
// '89 in my time! You, '90 is my year.
//
// You're weakenin' fast, YO! and I can tell it
// Your body's gettin' hot, so, so I can smell it
// So don't be mad and don't be sad
// 'Cause the lyrics belong to ICE, You can call me Dad
// You're pitchin' a fit, so step back and endure
// Let the witch doctor, Ice, do the dance to cure
// So come up close and don't be square
// You wanna battle me -- Anytime, anywhere
//
// You thought that I was weak, Boy, you're dead wrong
// So come on, everybody and sing this song
//
// Say -- Play that funky music Say, go white boy, go white boy go
// play that funky music Go white boy, go white boy, go
// Lay down and boogie and play that funky music till you die.
//
// Play that funky music Come on, Come on, let me hear
// Play that funky music white boy you say it, say it
// Play that funky music A little louder now
// Play that funky music, white boy Come on, Come on, Come on
// Play that funky music
