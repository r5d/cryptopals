// Copyright © 2020 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C11() {
	// Given an input `in`, this function AES encrypts `in` using a
	// randomly generate 16-byte key using ECB or CBC mode and returns the
	// cipher.
	encrypt := func(in []byte) []byte {
		// Generate random key.
		key, err := lib.RandomBytes(16)
		if err != nil {
			panic(err)
		}
		// Generate random initialization vector; needed for AES CBC.
		iv, err := lib.RandomBytes(16)
		if err != nil {
			panic(err)
		}

		// Add 5-10 bytes at the beginning and end of `in`
		in = append(lib.RandomBytesWithLengthBetween(5, 10), in...)
		in = append(in, lib.RandomBytesWithLengthBetween(5, 10)...)

		// Randomly encrypt `in` with AES in ECB or CBC mode.
		m := lib.RandomInt(0, 1)
		var out []byte
		if m == 0 {
			// Encrypt with AES in ECB mode.
			out = lib.AESEncryptECB(in, key)
		} else {
			// Encrypt with AES in CBC mode.
			out = lib.AESEncryptCBC(in, key, iv)
		}
		return out
	}
	p := lib.StrToBytes("YellowSubmarine YellowSubmarine YellowSubmarine")
	fmt.Printf("Input: %v (%d)\n", p, len(p))

	for i := 0; i < 10; i++ {
		o := encrypt(p)
		if lib.CipherUsesECB(o) != nil {
			fmt.Printf("%d -> Enciphered with ECB: %v (%d)\n", i, o, len(o))
		} else {
			fmt.Printf("%d -> Enciphered with CBC: %v (%d)\n", i, o, len(o))
		}
	}
}

// Output:
//
// Input: [89 101 108 108 111 119 83 117 98 109 97 114 105 110 101 32 89 101 108 108 111 119 83 117 98 109 97 114 105 110 101 32 89 101 108 108 111 119 83 117 98 109 97 114 105 110 101] (47)
// 0 -> Enciphered with ECB: [35 63 70 106 3 27 114 8 99 240 172 216 89 209 55 205 89 94 171 60 249 255 164 56 155 105 139 119 88 227 128 85 89 94 171 60 249 255 164 56 155 105 139 119 88 227 128 85 100 69 10 16 35 31 31 234 14 251 175 34 126 184 156 78 74 58 183 149 156 15 232 109 246 112 70 216 33 87 243 116] (80)
// 1 -> Enciphered with ECB: [18 201 52 83 85 1 183 97 83 46 80 47 210 66 95 170 139 140 233 57 139 29 181 203 30 234 210 131 196 201 167 79 139 140 233 57 139 29 181 203 30 234 210 131 196 201 167 79 107 30 127 14 185 211 45 142 79 188 207 85 251 116 23 13] (64)
// 2 -> Enciphered with CBC: [173 108 6 51 46 203 64 8 214 197 146 36 169 20 47 1 116 115 254 49 13 10 129 96 23 200 209 246 130 237 194 238 108 123 24 252 107 71 39 131 65 1 164 143 135 212 123 129 80 76 230 198 37 211 22 243 253 216 169 180 249 38 15 222 221 189 13 141 44 99 202 85 12 42 68 32 106 98 241 22] (80)
// 3 -> Enciphered with CBC: [237 155 152 90 211 21 101 93 106 196 92 63 166 144 104 168 91 116 211 231 226 162 144 235 109 156 191 190 74 46 184 143 107 90 154 252 168 230 62 237 29 35 120 203 177 167 25 89 123 10 170 60 28 84 240 58 218 250 37 139 185 22 115 114 89 135 48 45 148 21 17 70 56 215 182 17 194 84 127 128] (80)
// 4 -> Enciphered with CBC: [106 160 43 177 218 17 151 229 76 127 137 114 244 245 212 79 142 11 112 76 66 140 40 191 112 123 47 5 205 162 148 72 179 189 121 196 101 249 50 163 5 6 231 238 251 162 116 170 235 182 193 167 247 40 30 216 199 193 197 125 55 230 210 118 197 206 111 71 184 170 101 210 122 218 200 33 151 103 24 91] (80)
// 5 -> Enciphered with ECB: [31 115 245 176 106 204 71 231 250 63 38 183 178 36 128 42 150 92 237 76 38 231 137 13 154 88 38 166 181 38 108 184 150 92 237 76 38 231 137 13 154 88 38 166 181 38 108 184 121 22 5 14 100 129 72 33 68 50 245 53 222 56 207 194 152 160 26 204 137 115 80 207 161 248 167 128 161 34 37 255] (80)
// 6 -> Enciphered with CBC: [60 192 216 200 36 243 198 39 222 115 232 59 25 153 1 137 224 236 152 210 106 168 42 85 69 167 172 29 72 81 149 171 228 254 58 41 29 33 143 154 107 175 130 74 98 18 235 194 154 190 151 145 169 78 91 130 28 59 218 125 194 193 135 40] (64)
// 7 -> Enciphered with CBC: [50 237 250 245 103 150 32 123 15 219 69 7 198 88 37 198 111 204 154 114 233 127 48 129 219 196 157 239 62 160 191 70 212 153 172 43 201 60 94 89 159 34 140 228 227 85 147 59 79 190 166 148 225 56 75 79 132 128 9 52 167 246 86 107] (64)
// 8 -> Enciphered with CBC: [142 146 10 190 132 205 192 108 98 87 3 73 193 61 247 134 82 96 217 62 169 167 85 156 237 116 137 9 168 4 246 148 23 227 19 162 90 193 152 172 2 231 187 212 232 99 16 200 235 145 238 243 202 149 190 139 148 207 59 94 147 94 52 76] (64)
// 9 -> Enciphered with CBC: [123 187 2 27 230 38 221 59 203 150 190 252 10 58 52 77 69 11 110 177 3 154 209 89 181 103 217 120 216 194 182 230 90 15 97 240 184 255 157 189 56 198 1 138 75 254 53 45 100 97 145 166 28 194 129 175 177 98 7 190 255 12 30 31] (64)
