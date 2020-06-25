// little endian version of htons()

package rawsocket

import "encoding/binary"

// htons converts a uint16 to network byte order
func htons(x uint16) uint16 {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, x)
	return binary.BigEndian.Uint16(buf)
}
