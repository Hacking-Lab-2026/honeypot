package servers

import (
	"context"
	"fmt"
	"net"

	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/handlers"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

const ssdpBufferSize = 1500

type SSDPServer struct {
	addr          string
	destinationIP string
	handler       *handlers.SSDPHandler
	logger        ports.Logger
}

func NewSSDPServer(addr string, destinationIP string, handler *handlers.SSDPHandler, logger ports.Logger) *SSDPServer {
	return &SSDPServer{addr: addr, destinationIP: destinationIP, handler: handler, logger: logger}
}

func (s *SSDPServer) Addr() string { return s.addr }

func (s *SSDPServer) Start(ctx context.Context) error {
	s.logger.Info("Starting SSDP honeypot server on " + s.addr)

	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		s.logger.Error("Failed to resolve SSDP server address: " + err.Error())
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.logger.Error("Failed to listen on UDP for SSDP: " + err.Error())
		return err
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buffer := make([]byte, ssdpBufferSize)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.logger.Error("Error reading SSDP UDP packet: " + err.Error())
			continue
		}
		data := make([]byte, n)
		copy(data, buffer[:n])
		go s.handleRequest(conn, remoteAddr, data)
	}
}

func (s *SSDPServer) handleRequest(conn *net.UDPConn, remoteAddr *net.UDPAddr, payload []byte) {
	s.logger.Info(fmt.Sprintf("SSDP packet received from %s, %d bytes", remoteAddr, len(payload)))

	packets, err := s.handler.Handle(remoteAddr.IP.String(), remoteAddr.Port, s.destinationIP, payload)
	if err != nil {
		s.logger.Error("Error processing SSDP request from " + remoteAddr.String() + ": " + err.Error())
		return
	}
	for i, pkt := range packets {
		if _, err := conn.WriteToUDP(pkt, remoteAddr); err != nil {
			s.logger.Error(fmt.Sprintf(
				"Error sending SSDP response packet %d/%d to %s: %v",
				i+1, len(packets), remoteAddr, err,
			))
			return
		}
	}
}
