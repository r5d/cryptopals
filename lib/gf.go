// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// GF(2^8) Multiplication
// Adapted from
// https://matthewvaneerde.wordpress.com/efficient-multiplication-and-division-in-gf2
func GFMultiply(a, b byte) byte {
	if a == 0x00 || b == 0x00 {
		return 0x00
	}

	ans := uint16(logXPlusOneOf[a]) + uint16(logXPlusOneOf[b])
	if ans >= 255 {
		ans -= 255
	}
	return xPlusOneToThe[byte(ans)]
}

var xPlusOneToThe map[byte]byte = map[byte]byte{
	0: 0x01, 1: 0x03, 2: 0x05, 3: 0x0f, 4: 0x11,
	5: 0x33, 6: 0x55, 7: 0xff, 8: 0x1a, 9: 0x2e,
	10: 0x72, 11: 0x96, 12: 0xa1, 13: 0xf8, 14: 0x13,
	15: 0x35, 16: 0x5f, 17: 0xe1, 18: 0x38, 19: 0x48,
	20: 0xd8, 21: 0x73, 22: 0x95, 23: 0xa4, 24: 0xf7,
	25: 0x02, 26: 0x06, 27: 0x0a, 28: 0x1e, 29: 0x22,
	30: 0x66, 31: 0xaa, 32: 0xe5, 33: 0x34, 34: 0x5c,
	35: 0xe4, 36: 0x37, 37: 0x59, 38: 0xeb, 39: 0x26,
	40: 0x6a, 41: 0xbe, 42: 0xd9, 43: 0x70, 44: 0x90,
	45: 0xab, 46: 0xe6, 47: 0x31, 48: 0x53, 49: 0xf5,
	50: 0x04, 51: 0x0c, 52: 0x14, 53: 0x3c, 54: 0x44,
	55: 0xcc, 56: 0x4f, 57: 0xd1, 58: 0x68, 59: 0xb8,
	60: 0xd3, 61: 0x6e, 62: 0xb2, 63: 0xcd, 64: 0x4c,
	65: 0xd4, 66: 0x67, 67: 0xa9, 68: 0xe0, 69: 0x3b,
	70: 0x4d, 71: 0xd7, 72: 0x62, 73: 0xa6, 74: 0xf1,
	75: 0x08, 76: 0x18, 77: 0x28, 78: 0x78, 79: 0x88,
	80: 0x83, 81: 0x9e, 82: 0xb9, 83: 0xd0, 84: 0x6b,
	85: 0xbd, 86: 0xdc, 87: 0x7f, 88: 0x81, 89: 0x98,
	90: 0xb3, 91: 0xce, 92: 0x49, 93: 0xdb, 94: 0x76,
	95: 0x9a, 96: 0xb5, 97: 0xc4, 98: 0x57, 99: 0xf9,
	100: 0x10, 101: 0x30, 102: 0x50, 103: 0xf0, 104: 0x0b,
	105: 0x1d, 106: 0x27, 107: 0x69, 108: 0xbb, 109: 0xd6,
	110: 0x61, 111: 0xa3, 112: 0xfe, 113: 0x19, 114: 0x2b,
	115: 0x7d, 116: 0x87, 117: 0x92, 118: 0xad, 119: 0xec,
	120: 0x2f, 121: 0x71, 122: 0x93, 123: 0xae, 124: 0xe9,
	125: 0x20, 126: 0x60, 127: 0xa0, 128: 0xfb, 129: 0x16,
	130: 0x3a, 131: 0x4e, 132: 0xd2, 133: 0x6d, 134: 0xb7,
	135: 0xc2, 136: 0x5d, 137: 0xe7, 138: 0x32, 139: 0x56,
	140: 0xfa, 141: 0x15, 142: 0x3f, 143: 0x41, 144: 0xc3,
	145: 0x5e, 146: 0xe2, 147: 0x3d, 148: 0x47, 149: 0xc9,
	150: 0x40, 151: 0xc0, 152: 0x5b, 153: 0xed, 154: 0x2c,
	155: 0x74, 156: 0x9c, 157: 0xbf, 158: 0xda, 159: 0x75,
	160: 0x9f, 161: 0xba, 162: 0xd5, 163: 0x64, 164: 0xac,
	165: 0xef, 166: 0x2a, 167: 0x7e, 168: 0x82, 169: 0x9d,
	170: 0xbc, 171: 0xdf, 172: 0x7a, 173: 0x8e, 174: 0x89,
	175: 0x80, 176: 0x9b, 177: 0xb6, 178: 0xc1, 179: 0x58,
	180: 0xe8, 181: 0x23, 182: 0x65, 183: 0xaf, 184: 0xea,
	185: 0x25, 186: 0x6f, 187: 0xb1, 188: 0xc8, 189: 0x43,
	190: 0xc5, 191: 0x54, 192: 0xfc, 193: 0x1f, 194: 0x21,
	195: 0x63, 196: 0xa5, 197: 0xf4, 198: 0x07, 199: 0x09,
	200: 0x1b, 201: 0x2d, 202: 0x77, 203: 0x99, 204: 0xb0,
	205: 0xcb, 206: 0x46, 207: 0xca, 208: 0x45, 209: 0xcf,
	210: 0x4a, 211: 0xde, 212: 0x79, 213: 0x8b, 214: 0x86,
	215: 0x91, 216: 0xa8, 217: 0xe3, 218: 0x3e, 219: 0x42,
	220: 0xc6, 221: 0x51, 222: 0xf3, 223: 0x0e, 224: 0x12,
	225: 0x36, 226: 0x5a, 227: 0xee, 228: 0x29, 229: 0x7b,
	230: 0x8d, 231: 0x8c, 232: 0x8f, 233: 0x8a, 234: 0x85,
	235: 0x94, 236: 0xa7, 237: 0xf2, 238: 0x0d, 239: 0x17,
	240: 0x39, 241: 0x4b, 242: 0xdd, 243: 0x7c, 244: 0x84,
	245: 0x97, 246: 0xa2, 247: 0xfd, 248: 0x1c, 249: 0x24,
	250: 0x6c, 251: 0xb4, 252: 0xc7, 253: 0x52, 254: 0xf6,
}

// Inverse of xPlusOneToThe
var logXPlusOneOf map[byte]byte = map[byte]byte{
	0x01: 0, 0x02: 25, 0x03: 1, 0x04: 50, 0x05: 2,
	0x06: 26, 0x07: 198, 0x08: 75, 0x09: 199, 0x0a: 27,
	0x0b: 104, 0x0c: 51, 0x0d: 238, 0x0e: 223, 0x0f: 3,
	0x10: 100, 0x11: 4, 0x12: 224, 0x13: 14, 0x14: 52,
	0x15: 141, 0x16: 129, 0x17: 239, 0x18: 76, 0x19: 113,
	0x1a: 8, 0x1b: 200, 0x1c: 248, 0x1d: 105, 0x1e: 28,
	0x1f: 193, 0x20: 125, 0x21: 194, 0x22: 29, 0x23: 181,
	0x24: 249, 0x25: 185, 0x26: 39, 0x27: 106, 0x28: 77,
	0x29: 228, 0x2a: 166, 0x2b: 114, 0x2c: 154, 0x2d: 201,
	0x2e: 9, 0x2f: 120, 0x30: 101, 0x31: 47, 0x32: 138,
	0x33: 5, 0x34: 33, 0x35: 15, 0x36: 225, 0x37: 36,
	0x38: 18, 0x39: 240, 0x3a: 130, 0x3b: 69, 0x3c: 53,
	0x3d: 147, 0x3e: 218, 0x3f: 142, 0x40: 150, 0x41: 143,
	0x42: 219, 0x43: 189, 0x44: 54, 0x45: 208, 0x46: 206,
	0x47: 148, 0x48: 19, 0x49: 92, 0x4a: 210, 0x4b: 241,
	0x4c: 64, 0x4d: 70, 0x4e: 131, 0x4f: 56, 0x50: 102,
	0x51: 221, 0x52: 253, 0x53: 48, 0x54: 191, 0x55: 6,
	0x56: 139, 0x57: 98, 0x58: 179, 0x59: 37, 0x5a: 226,
	0x5b: 152, 0x5c: 34, 0x5d: 136, 0x5e: 145, 0x5f: 16,
	0x60: 126, 0x61: 110, 0x62: 72, 0x63: 195, 0x64: 163,
	0x65: 182, 0x66: 30, 0x67: 66, 0x68: 58, 0x69: 107,
	0x6a: 40, 0x6b: 84, 0x6c: 250, 0x6d: 133, 0x6e: 61,
	0x6f: 186, 0x70: 43, 0x71: 121, 0x72: 10, 0x73: 21,
	0x74: 155, 0x75: 159, 0x76: 94, 0x77: 202, 0x78: 78,
	0x79: 212, 0x7a: 172, 0x7b: 229, 0x7c: 243, 0x7d: 115,
	0x7e: 167, 0x7f: 87, 0x80: 175, 0x81: 88, 0x82: 168,
	0x83: 80, 0x84: 244, 0x85: 234, 0x86: 214, 0x87: 116,
	0x88: 79, 0x89: 174, 0x8a: 233, 0x8b: 213, 0x8c: 231,
	0x8d: 230, 0x8e: 173, 0x8f: 232, 0x90: 44, 0x91: 215,
	0x92: 117, 0x93: 122, 0x94: 235, 0x95: 22, 0x96: 11,
	0x97: 245, 0x98: 89, 0x99: 203, 0x9a: 95, 0x9b: 176,
	0x9c: 156, 0x9d: 169, 0x9e: 81, 0x9f: 160, 0xa0: 127,
	0xa1: 12, 0xa2: 246, 0xa3: 111, 0xa4: 23, 0xa5: 196,
	0xa6: 73, 0xa7: 236, 0xa8: 216, 0xa9: 67, 0xaa: 31,
	0xab: 45, 0xac: 164, 0xad: 118, 0xae: 123, 0xaf: 183,
	0xb0: 204, 0xb1: 187, 0xb2: 62, 0xb3: 90, 0xb4: 251,
	0xb5: 96, 0xb6: 177, 0xb7: 134, 0xb8: 59, 0xb9: 82,
	0xba: 161, 0xbb: 108, 0xbc: 170, 0xbd: 85, 0xbe: 41,
	0xbf: 157, 0xc0: 151, 0xc1: 178, 0xc2: 135, 0xc3: 144,
	0xc4: 97, 0xc5: 190, 0xc6: 220, 0xc7: 252, 0xc8: 188,
	0xc9: 149, 0xca: 207, 0xcb: 205, 0xcc: 55, 0xcd: 63,
	0xce: 91, 0xcf: 209, 0xd0: 83, 0xd1: 57, 0xd2: 132,
	0xd3: 60, 0xd4: 65, 0xd5: 162, 0xd6: 109, 0xd7: 71,
	0xd8: 20, 0xd9: 42, 0xda: 158, 0xdb: 93, 0xdc: 86,
	0xdd: 242, 0xde: 211, 0xdf: 171, 0xe0: 68, 0xe1: 17,
	0xe2: 146, 0xe3: 217, 0xe4: 35, 0xe5: 32, 0xe6: 46,
	0xe7: 137, 0xe8: 180, 0xe9: 124, 0xea: 184, 0xeb: 38,
	0xec: 119, 0xed: 153, 0xee: 227, 0xef: 165, 0xf0: 103,
	0xf1: 74, 0xf2: 237, 0xf3: 222, 0xf4: 197, 0xf5: 49,
	0xf6: 254, 0xf7: 24, 0xf8: 13, 0xf9: 99, 0xfa: 140,
	0xfb: 128, 0xfc: 192, 0xfd: 247, 0xfe: 112, 0xff: 7,
}
