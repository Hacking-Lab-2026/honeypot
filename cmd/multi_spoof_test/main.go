package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

func makeNTPRequest() []byte {
	b := make([]byte, 48)
	b[0] = 0x1B
	return b
}

func worker(srcIP string, target string, packets int, delay time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()
	rAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		log.Printf("resolve target %s: %v", target, err)
		return
	}
	lAddr := &net.UDPAddr{IP: net.ParseIP(srcIP), Port: 0}
	conn, err := net.DialUDP("udp", lAddr, rAddr)
	if err != nil {
		log.Printf("bind %s -> %s: %v", srcIP, target, err)
		return
	}
	defer conn.Close()
	req := makeNTPRequest()
	buf := make([]byte, 512)
	for i := 0; i < packets; i++ {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(req); err != nil {
			log.Printf("%s write: %v", srcIP, err)
			return
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("%s read (may be dropped): %v", srcIP, err)
		} else {
			log.Printf("%s got %d bytes", srcIP, n)
		}
		time.Sleep(delay)
	}
}

func main() {
	target := flag.String("target", "127.0.0.1:123", "honeypot target address")
	count := flag.Int("count", 50, "number of spoofed source IPs to use")
	packets := flag.Int("packets", 1, "packets to send per source")
	delayMs := flag.Int("delay", 10, "delay ms between packets per source")
	base := flag.String("base", "127.0.0.", "base prefix for source IPs; append consecutive integers")
	start := flag.Int("start", 2, "start index to append to base for first source IP")
	flag.Parse()
	var wg sync.WaitGroup
	for i := 0; i < *count; i++ {
		src := fmt.Sprintf("%s%d", *base, *start+i)
		wg.Add(1)
		go worker(src, *target, *packets, time.Duration(*delayMs)*time.Millisecond, &wg)
	}
	wg.Wait()
}
