package internal

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/sirupsen/logrus"
	"log"
	"os"
	"runtime"
	"time"
)

/**
Compare the pcap files given
Runs in parallel with the given number of workers
*/

func ComparePcaps(files FileArgs, workers int) (packetsIn uint64, packetsOut uint64, err error) {
	modifiedHandle, err := pcap.OpenOffline(files.ModifiedFile)
	if err != nil {
		return
	}
	defer modifiedHandle.Close()
	logrus.Debug("Opened modified file")
	f, err := os.Create(files.OutputFile)
	if err != nil {
		return
	}
	w := pcapgo.NewWriter(f)
	defer f.Close()
	logrus.Debug("Created output file")

	packetSource := gopacket.NewPacketSource(modifiedHandle, modifiedHandle.LinkType())
	err = w.WriteFileHeader(65535, modifiedHandle.LinkType())
	if err != nil {
		return
	}
	logrus.Debug("Written header to output file")
	// Channels for workers
	//jobs := make(chan gopacket.Packet, 1000)
	//results := make(chan gopacket.Packet, 1000)
	//errorChan := make(chan error, 100)

	sourceMap := make(map[string]PacketPlaceholder)
	err = readPacketsToMap(sourceMap, files.SourceFile)
	if err != nil {
		log.Fatalln(err)
	}
	packetsIn = uint64(len(sourceMap))

	for packet := range packetSource.Packets() {
		sha := hashPacket(packet)
		packet.Metadata().Timestamp = sourceMap[sha].Timestamp
		err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			return
		}
		packetsOut++
	}

	return
}

func readPacketsToMap(m map[string]PacketPlaceholder, originalPath string) error {
	originalHandle, err := pcap.OpenOffline(originalPath)
	defer originalHandle.Close()
	if err != nil {
		return err
	}
	logrus.Debugln("Opened original file")
	packetSource := gopacket.NewPacketSource(originalHandle, originalHandle.LinkType())
	packetCount := 0
	logrus.Debugln("Created packet source")
	var now time.Time
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		now = time.Now()
	}
	for packet := range packetSource.Packets() {
		sha := hashPacket(packet)
		placeholder := PacketPlaceholder{packet.Metadata().Timestamp}
		m[sha] = placeholder
		packetCount++
	}
	if !now.IsZero() {
		elapsed := time.Now().Sub(now)
		logrus.Debugf("Time elapsed is %f seconds", elapsed.Seconds())
	}
	PrintMemUsage()
	logrus.Infof("Info: Finished Reading %d Packets into map", packetCount)
	return nil
}

func hashPacket(packet gopacket.Packet) string {
	h := sha1.New()        // Create hash object
	h.Write(packet.Data()) // Write the hash
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

func PrintMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}
