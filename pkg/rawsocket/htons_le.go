// little endian version of htons()
// +build 386 amd64 amd64p32 arm arm64 mipsle mips64le mips64p32le ppc64le riscv riscv64 wasm

package rawsocket

import "encoding/binary"

// htons converts a uint16 to network byte order
func htons(x uint16) uint16 {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, x)
	return binary.BigEndian.Uint16(buf)
}
