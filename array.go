package main

func isAllZeroes(b []byte) bool {
	z := true
	for _, x := range b {
		if x != 0 {
			z = false
			break
		}
	}
	return z
}

func toArray3(b []byte) (ba [3]byte) {
	for i, x := range b {
		ba[i] = x
	}
	return
}

func toSlice3(b []byte, a [3]byte) {
	for i, x := range a {
		b[i] = x
	}
}

func toArray4(b []byte) (ba [4]byte) {
	for i, x := range b {
		ba[i] = x
	}
	return
}

func toSlice4(b []byte, a [4]byte) {
	for i, x := range a {
		b[i] = x
	}
}

func toArray16(b []byte) (ba [16]byte) {
	for i, x := range b {
		ba[i] = x
	}
	return
}

func toSlice16(b []byte, a [16]byte) {
	for i, x := range a {
		b[i] = x
	}
}
