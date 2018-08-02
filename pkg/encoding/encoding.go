// Package encoding is adapted from golang.org/x/crypto/ssh.
package encoding

import "encoding/binary"

func Uint32(n uint32) []byte {
	return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func String(s string) []byte {
	return append(Uint32(uint32(len(s))), s...)
}

func ParseUint32(in []byte) (out uint32, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

func ParseString(in []byte) (out string, rest []byte, ok bool) {
	length, rest, ok := ParseUint32(in)
	if !ok {
		return
	}
	if uint32(len(rest)) < length {
		return
	}
	out = string(rest[:length])
	rest = rest[length:]
	ok = true
	return
}
