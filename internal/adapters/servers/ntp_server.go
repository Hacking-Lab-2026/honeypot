package servers

import (
	"context"
	"net"

	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/handlers"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

const ntpBufferSize = 512

// NTPServer listens for UDP NTP requests on a single address and dispatches each packet to a goroutine.
type NTPServer struct {
	addr          string
	destinationIP string
	handler       *handlers.NTPHandler
	logger        ports.Logger
}

func NewNTPServer(addr string, destinationIP string, handler *handlers.NTPHandler, logger ports.Logger) *NTPServer {
	return &NTPServer{addr: addr, destinationIP: destinationIP, handler: handler, logger: logger}
}

func (s *NTPServer) Addr() string { return s.addr }

func (s *NTPServer) Start(ctx context.Context) error {
	s.logger.Info("Starting NTP honeypot server on " + s.addr)

	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		s.logger.Error("Failed to resolve NTP server address: " + err.Error())
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.logger.Error("Failed to listen on UDP for NTP: " + err.Error())
		return err
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buffer := make([]byte, ntpBufferSize)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.logger.Error("Error reading NTP UDP packet: " + err.Error())
			continue
		}
		data := make([]byte, n)
		copy(data, buffer[:n])
		go s.handleRequest(conn, remoteAddr, data)
	}
}

func (s *NTPServer) handleRequest(conn *net.UDPConn, remoteAddr *net.UDPAddr, payload []byte) {
	response, err := s.handler.Handle(remoteAddr.IP.String(), remoteAddr.Port, s.destinationIP, payload)
	if err != nil {
		s.logger.Error("Error processing NTP request from " + remoteAddr.String() + ": " + err.Error())
		return
	}
	if len(response) > 0 {
		if _, err := conn.WriteToUDP(response, remoteAddr); err != nil {
			s.logger.Error("Error sending NTP response to " + remoteAddr.String() + ": " + err.Error())
		}
	}
}
