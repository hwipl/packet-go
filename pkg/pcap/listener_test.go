package pcap

import (
	"log"
	"net"
	"os"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type testHandler struct {
	packetHandled bool
	timerHandled  bool
}

func (th *testHandler) HandlePacket(packet gopacket.Packet) {
	th.packetHandled = true
}

func (th *testHandler) HandleTimer() {
	th.timerHandled = true
}

func TestListenerGetFirstPcapInterface(t *testing.T) {
	var listener Listener
	listener.getFirstPcapInterface()
	if listener.Device == "" {
		t.Errorf("Device = \"\", want != \"\"")
	}
}

func testListenerPcapCreateDumpFile() string {
	// prepare creation of packet
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// create ethernet header
	srcMAC, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		log.Fatal(err)
	}
	dstMAC := srcMAC
	eth := layers.Ethernet{
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
	}

	// serialize packet to buffer
	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, opts, &eth)
	if err != nil {
		log.Fatal(err)
	}
	packet := buf.Bytes()

	// create temporary pcap file
	tmpFile, err := os.CreateTemp("", "listener.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = tmpFile.Close() }()

	// write packets of fake tcp connection to pcap file
	w := pcapgo.NewWriter(tmpFile)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		log.Fatal(err)
	}
	if err := w.WritePacket(gopacket.CaptureInfo{
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet); err != nil {
		log.Fatal(err)
	}

	return tmpFile.Name()
}

func TestListenerPcap(t *testing.T) {
	// create temporary pcap file
	tmpFile := testListenerPcapCreateDumpFile()
	defer func() { _ = os.Remove(tmpFile) }()

	// prepare listener
	var testHandler testHandler
	var listener Listener
	listener.PacketHandler = &testHandler
	listener.File = tmpFile

	// let listener handle the packet
	listener.Prepare()
	listener.Loop()

	// check results
	want := true
	got := testHandler.packetHandled
	if got != want {
		t.Errorf("got = %t; want %t", got, want)
	}
}

func TestListenPcapFilter(t *testing.T) {
	var want, got bool

	// create temporary pcap file
	tmpFile := testListenerPcapCreateDumpFile()
	defer func() { _ = os.Remove(tmpFile) }()

	// prepare listener
	var testHandler testHandler
	var listener Listener
	listener.PacketHandler = &testHandler
	listener.File = tmpFile

	// let listener handle the packet with not matching filter
	listener.Filter = "ether host 00:00:5e:00:53:02"
	listener.Prepare()
	listener.Loop()

	// check results
	want = false
	got = testHandler.packetHandled
	if got != want {
		t.Errorf("got = %t; want %t", got, want)
	}

	// let listener handle the packet with matching filter
	listener.Filter = "ether host 00:00:5e:00:53:01"
	listener.Prepare()
	listener.Loop()

	// check results
	want = true
	got = testHandler.packetHandled
	if got != want {
		t.Errorf("got = %t; want %t", got, want)
	}
}
