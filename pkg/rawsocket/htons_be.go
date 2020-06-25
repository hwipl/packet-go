// big endian version of htons()
// +build armbe arm64be mips mips64 mips64p32 ppc ppc64 s390 s390x sparc sparc64

package rawsocket

func htons(x uint16) uint16 {
	return x
}
