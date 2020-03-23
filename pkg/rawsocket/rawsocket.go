package rawsocket

import (
	"log"
	"net"

	"golang.org/x/sys/unix"
)

// RawSocket stores a raw socket
type RawSocket struct {
	fd      int
	devName string
	dev     *net.Interface
	addr    *unix.SockaddrLinklayer
}

// Close closes the raw socket
func (r *RawSocket) Close() {
	unix.Close(r.fd)
}

// Send sends data out of the raw socket
func (r *RawSocket) Send(data []byte) {
	err := unix.Sendto(r.fd, data, 0, r.addr)
	if err != nil {
		log.Fatal(err)
	}
}

// NewRawSocket creates a new raw socket for device
func NewRawSocket(device string) *RawSocket {
	// create raw socket
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_ALL)
	if err != nil {
		log.Fatal(err)
	}

	// get loopback interface
	dev, err := net.InterfaceByName(device)
	if err != nil {
		log.Fatal(err)
	}

	// create sockaddr
	addr := &unix.SockaddrLinklayer{
		Protocol: unix.ETH_P_IP,
		Ifindex:  dev.Index,
		Halen:    6,
	}

	// create raw socket and return it
	return &RawSocket{
		fd:      fd,
		devName: device,
		dev:     dev,
		addr:    addr,
	}
}
