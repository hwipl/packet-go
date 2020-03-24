package tcp

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Peer stores a peer of a TCP connection
type Peer struct {
	mac   net.HardwareAddr
	ip    net.IP
	port  uint16
	seq   uint32
	ack   uint32
	flags struct {
		syn bool
		ack bool
		fin bool
	}
	options []layers.TCPOption
}

// NewPeer creates a new peer of a tcp connection with the MAC address mac, the
// IP address ip, the TCP port port, and the TCP initial sequence number isn
func NewPeer(mac, ip string, port uint16, isn uint32) *Peer {
	// parse mac address
	macAddr, err := net.ParseMAC(mac)
	if err != nil {
		log.Fatal(err)
	}

	// parse ip address
	ipAddr := net.ParseIP(ip)

	// create and return peer
	peer := Peer{
		mac:  macAddr,
		ip:   ipAddr,
		port: port,
		seq:  isn,
	}
	return &peer
}

// Conn stores a TCP connection
type Conn struct {
	Client  *Peer
	Server  *Peer
	Options struct {
		SYN    []layers.TCPOption
		SYNACK []layers.TCPOption
		ACK    []layers.TCPOption
	}
	Packets [][]byte
}

// createPacket creates a TCP packet between the TCP peers sender and receiver
// that contains payload
func (c *Conn) createPacket(sender, receiver *Peer, payload []byte) {
	// prepare creation of fake packet
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// create ethernet header
	eth := layers.Ethernet{
		SrcMAC:       sender.mac,
		DstMAC:       receiver.mac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// create ip header
	ip := layers.IPv4{
		Version:  4,
		Flags:    layers.IPv4DontFragment,
		Id:       1, // TODO: update? remove?
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    sender.ip,
		DstIP:    receiver.ip,
	}
	// create tcp header
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(sender.port),
		DstPort: layers.TCPPort(receiver.port),
		SYN:     sender.flags.syn,
		ACK:     sender.flags.ack,
		FIN:     sender.flags.fin,
		Seq:     sender.seq,
		Ack:     sender.ack,
		Window:  64000,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	// add tcp options if present
	if sender.options != nil {
		tcp.Options = sender.options
	}

	// serialize packet to buffer
	var err error
	buf := gopacket.NewSerializeBuffer()
	if payload != nil {
		// with payload
		pl := gopacket.Payload(payload)
		err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp,
			pl)
	} else {
		// without payload
		err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
	}
	if err != nil {
		log.Fatal(err)
	}

	// append packet to the list of all packets
	packets := make([][]byte, len(c.Packets)+1)
	for i, p := range c.Packets {
		packets[i] = p
	}
	packets[len(packets)-1] = buf.Bytes()
	c.Packets = packets
}

// Connect creates the packets of the three way handshake between the peers of
// the TCP connection
func (c *Conn) Connect() {
	// create fake SYN packet
	c.Client.flags.syn = true
	c.Client.flags.ack = false
	c.Client.flags.fin = false
	c.Client.ack = uint32(0)
	c.Client.options = c.Options.SYN
	c.createPacket(c.Client, c.Server, nil)
	c.Client.seq++

	// create fake SYN, ACK packet
	c.Server.flags.syn = true
	c.Server.flags.ack = true
	c.Server.flags.fin = false
	c.Server.ack = c.Client.seq
	c.Server.options = c.Options.SYNACK
	c.createPacket(c.Server, c.Client, nil)
	c.Server.seq++

	// remove options from client and server
	c.Client.options = c.Options.ACK
	c.Server.options = c.Options.ACK

	// create fake ACK packet
	c.Client.flags.syn = false
	c.Client.flags.ack = true
	c.Client.flags.fin = false
	c.Client.ack = c.Server.seq
	//c.server.options = c.options
	c.createPacket(c.Client, c.Server, nil)
}

// Send creates packets for the payload sent from sender to receiver and its
// acknowledgment for the TCP connection
func (c *Conn) Send(sender, receiver *Peer, payload []byte) {
	// create fake payload packet
	sender.flags.syn = false
	sender.flags.ack = true
	sender.flags.fin = false
	sender.ack = receiver.seq
	c.createPacket(sender, receiver, payload)
	sender.seq += uint32(len(payload))

	// create fake ACK packet
	receiver.flags.syn = false
	receiver.flags.ack = true
	receiver.flags.fin = false
	receiver.ack = sender.seq
	c.createPacket(receiver, sender, nil)
}

// Disconnect creates the packets for a client side initiated TCP connection
// termination
func (c *Conn) Disconnect() {
	// create fake FIN, ACK packet
	c.Client.flags.syn = false
	c.Client.flags.ack = true
	c.Client.flags.fin = true
	c.Client.ack = c.Server.seq
	c.createPacket(c.Client, c.Server, nil)
	c.Client.seq++

	// create fake FIN, ACK packet
	c.Server.flags.syn = false
	c.Server.flags.ack = true
	c.Server.flags.fin = true
	c.Server.ack = c.Client.seq
	c.createPacket(c.Server, c.Client, nil)
	c.Server.seq++

	// create fake ACK packet
	c.Client.flags.syn = false
	c.Client.flags.ack = true
	c.Client.flags.fin = false
	c.Client.ack = c.Server.seq
	c.createPacket(c.Client, c.Server, nil)
}

// NewConn creates a new TCP connection between the peers client and server
func NewConn(client, server *Peer) *Conn {
	conn := Conn{
		Client: client,
		Server: server,
	}
	return &conn
}
