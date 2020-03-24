package tcp

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Peer stores a peer of a TCP connection
type Peer struct {
	MAC   net.HardwareAddr
	IP    net.IP
	Port  uint16
	Seq   uint32
	Ack   uint32
	Flags struct {
		SYN bool
		ACK bool
		FIN bool
	}
	Options []layers.TCPOption
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
		MAC:  macAddr,
		IP:   ipAddr,
		Port: port,
		Seq:  isn,
	}
	return &peer
}

// Conn stores a TCP connection
type Conn struct {
	// Client is the client initiating and terminating this connection
	Client *Peer

	// Server is the server end of this connection
	Server *Peer

	// Options contains TCP options for different states of the TCP
	// connection: SYN stores the options for the initial SYN packet,
	// SYNACK for the SYNACK packet, ACK for the ACK packet and the
	// remainder of this connection
	Options struct {
		SYN    []layers.TCPOption
		SYNACK []layers.TCPOption
		ACK    []layers.TCPOption
	}

	// Packets is a list of all packets as byte slices in this connection
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
		SrcMAC:       sender.MAC,
		DstMAC:       receiver.MAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// create ip header
	ip := layers.IPv4{
		Version:  4,
		Flags:    layers.IPv4DontFragment,
		Id:       1, // TODO: update? remove?
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    sender.IP,
		DstIP:    receiver.IP,
	}
	// create tcp header
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(sender.Port),
		DstPort: layers.TCPPort(receiver.Port),
		SYN:     sender.Flags.SYN,
		ACK:     sender.Flags.ACK,
		FIN:     sender.Flags.FIN,
		Seq:     sender.Seq,
		Ack:     sender.Ack,
		Window:  64000,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	// add tcp options if present
	if sender.Options != nil {
		tcp.Options = sender.Options
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
	c.Client.Flags.SYN = true
	c.Client.Flags.ACK = false
	c.Client.Flags.FIN = false
	c.Client.Ack = uint32(0)
	c.Client.Options = c.Options.SYN
	c.createPacket(c.Client, c.Server, nil)
	c.Client.Seq++

	// create fake SYN, ACK packet
	c.Server.Flags.SYN = true
	c.Server.Flags.ACK = true
	c.Server.Flags.FIN = false
	c.Server.Ack = c.Client.Seq
	c.Server.Options = c.Options.SYNACK
	c.createPacket(c.Server, c.Client, nil)
	c.Server.Seq++

	// remove options from client and server
	c.Client.Options = c.Options.ACK
	c.Server.Options = c.Options.ACK

	// create fake ACK packet
	c.Client.Flags.SYN = false
	c.Client.Flags.ACK = true
	c.Client.Flags.FIN = false
	c.Client.Ack = c.Server.Seq
	//c.server.options = c.options
	c.createPacket(c.Client, c.Server, nil)
}

// Send creates packets for the payload sent from sender to receiver and its
// acknowledgment for the TCP connection
func (c *Conn) Send(sender, receiver *Peer, payload []byte) {
	// create fake payload packet
	sender.Flags.SYN = false
	sender.Flags.ACK = true
	sender.Flags.FIN = false
	sender.Ack = receiver.Seq
	c.createPacket(sender, receiver, payload)
	sender.Seq += uint32(len(payload))

	// create fake ACK packet
	receiver.Flags.SYN = false
	receiver.Flags.ACK = true
	receiver.Flags.FIN = false
	receiver.Ack = sender.Seq
	c.createPacket(receiver, sender, nil)
}

// Disconnect creates the packets for a client side initiated TCP connection
// termination
func (c *Conn) Disconnect() {
	// create fake FIN, ACK packet
	c.Client.Flags.SYN = false
	c.Client.Flags.ACK = true
	c.Client.Flags.FIN = true
	c.Client.Ack = c.Server.Seq
	c.createPacket(c.Client, c.Server, nil)
	c.Client.Seq++

	// create fake FIN, ACK packet
	c.Server.Flags.SYN = false
	c.Server.Flags.ACK = true
	c.Server.Flags.FIN = true
	c.Server.Ack = c.Client.Seq
	c.createPacket(c.Server, c.Client, nil)
	c.Server.Seq++

	// create fake ACK packet
	c.Client.Flags.SYN = false
	c.Client.Flags.ACK = true
	c.Client.Flags.FIN = false
	c.Client.Ack = c.Server.Seq
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
