package tcp

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCPPeer struct {
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

func NewTCPPeer(mac, ip string, port uint16, isn uint32) *TCPPeer {
	// parse mac address
	macAddr, err := net.ParseMAC(mac)
	if err != nil {
		log.Fatal(err)
	}

	// parse ip address
	ipAddr := net.ParseIP(ip)

	// create and return peer
	peer := TCPPeer{
		mac:  macAddr,
		ip:   ipAddr,
		port: port,
		seq:  isn,
	}
	return &peer
}

type TCPConn struct {
	client  *TCPPeer
	server  *TCPPeer
	packets [][]byte
}

func (c *TCPConn) createSegment(sender, receiver *TCPPeer, payload []byte) {
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
	packets := make([][]byte, len(c.packets)+1)
	for i, p := range c.packets {
		packets[i] = p
	}
	packets[len(packets)-1] = buf.Bytes()
	c.packets = packets
}

func (c *TCPConn) connect() {
	// create fake SYN packet
	c.client.flags.syn = true
	c.client.flags.ack = false
	c.client.flags.fin = false
	c.client.ack = uint32(0)
	c.createSegment(c.client, c.server, nil)
	c.client.seq += 1

	// create fake SYN, ACK packet
	c.server.flags.syn = true
	c.server.flags.ack = true
	c.server.flags.fin = false
	c.server.ack = c.client.seq
	c.createSegment(c.server, c.client, nil)
	c.server.seq += 1

	// create fake ACK packet
	c.client.flags.syn = false
	c.client.flags.ack = true
	c.client.flags.fin = false
	c.client.ack = c.server.seq
	c.createSegment(c.client, c.server, nil)
}

func (c *TCPConn) send(sender, receiver *TCPPeer, payload []byte) {
	// create fake payload packet
	sender.flags.syn = false
	sender.flags.ack = true
	sender.flags.fin = false
	sender.ack = receiver.seq
	c.createSegment(sender, receiver, payload)
	sender.seq += uint32(len(payload))

	// create fake ACK packet
	receiver.flags.syn = false
	receiver.flags.ack = true
	receiver.flags.fin = false
	receiver.ack = sender.seq
	c.createSegment(receiver, sender, nil)
}

func (c *TCPConn) disconnect() {
	// create fake FIN, ACK packet
	c.client.flags.syn = false
	c.client.flags.ack = true
	c.client.flags.fin = true
	c.client.ack = c.server.seq
	c.createSegment(c.client, c.server, nil)
	c.client.seq += 1

	// create fake FIN, ACK packet
	c.server.flags.syn = false
	c.server.flags.ack = true
	c.server.flags.fin = true
	c.server.ack = c.client.seq
	c.createSegment(c.server, c.client, nil)
	c.server.seq += 1

	// create fake ACK packet
	c.client.flags.syn = false
	c.client.flags.ack = true
	c.client.flags.fin = false
	c.client.ack = c.server.seq
	c.createSegment(c.client, c.server, nil)
}

func NewTCPConn(client, server *TCPPeer) *TCPConn {
	conn := TCPConn{
		client: client,
		server: server,
	}
	return &conn
}
