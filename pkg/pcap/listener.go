package pcap

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Listener is a pcap listener that reads packets from a file or device and
// calls Handlers for packets and timer events
type Listener struct {
	pcapHandle *pcap.Handle

	PacketHandler PacketHandler

	Timer        time.Duration
	TimerHandler TimerHandler

	File    string
	Device  string
	Promisc bool
	Snaplen int
	Timeout time.Duration
	Filter  string
	MaxPkts int
	MaxTime time.Duration
}

// getFirstPcapInterface sets the first network interface found by pcap
func (l *Listener) getFirstPcapInterface() {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	if len(ifs) > 0 {
		l.Device = ifs[0].Name
		return
	}
	log.Fatal("No network interface found")
}

// Prepare prepares the pcap listener for the listen function
func (l *Listener) Prepare() {
	// open pcap handle
	var pcapErr error
	var startText string
	if l.File == "" {
		// set pcap timeout
		timeout := pcap.BlockForever
		if l.Timeout > 0 {
			timeout = l.Timeout
		}

		// set interface
		if l.Device == "" {
			l.getFirstPcapInterface()
		}

		// open device
		l.pcapHandle, pcapErr = pcap.OpenLive(l.Device,
			int32(l.Snaplen), l.Promisc, timeout)
		startText = fmt.Sprintf("Listening on interface %s:\n",
			l.Device)
	} else {
		// open pcap file
		l.pcapHandle, pcapErr = pcap.OpenOffline(l.File)
		startText = fmt.Sprintf("Reading packets from file %s:\n",
			l.File)
	}
	if pcapErr != nil {
		log.Fatal(pcapErr)
	}
	if l.Filter != "" {
		if err := l.pcapHandle.SetBPFFilter(l.Filter); err != nil {
			log.Fatal(pcapErr)
		}
	}
	log.Printf(startText)
}

// Loop implements the listen loop for the listen function
func (l *Listener) Loop() {
	defer l.pcapHandle.Close()

	// make sure there is a packet handler
	if l.PacketHandler == nil {
		log.Fatal("no packet handler set")
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(l.pcapHandle,
		l.pcapHandle.LinkType())
	packets := packetSource.Packets()

	// setup timer and check timer handler
	ticker := time.Tick(l.Timer)
	if ticker != nil && l.TimerHandler == nil {
		log.Fatal("timer used but no timer handler set")
	}

	// set stop time if configured
	stop := make(<-chan time.Time)
	if l.MaxTime > 0 {
		stop = time.After(l.MaxTime)
	}

	// handle packets and timer events
	count := 0
	for {
		select {
		case packet := <-packets:
			if packet == nil {
				return
			}
			l.PacketHandler.HandlePacket(packet)
			count++
			if l.MaxPkts > 0 && count == l.MaxPkts {
				return
			}
		case <-ticker:
			l.TimerHandler.HandleTimer()
		case <-stop:
			return
		}
	}

}
