package enc

func FixedXOR(a, b string) string {
	cs := ""
	if len(a) != len(b) {
		return cs
	}

	ab := []byte(a)
	bb := []byte(b)
	for i := 0; i < len(ab); i++ {
		p := HexCharToDec(ab[i])
		q := HexCharToDec(bb[i])
		r := DecToHexChar(p ^ q)

		cs += string(r)
	}
	return cs
}
