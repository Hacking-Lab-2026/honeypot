package servers

import (
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/handlers"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
	"net"
)

// Server represents a UDP honeypot server endpoint
type Server struct {
	addr    string
	handler *handlers.ProbeHandler
	logger  ports.Logger
}

// NewServer creates a new UDP server
func NewServer(addr string, handler *handlers.ProbeHandler, logger ports.Logger) *Server {
	return &Server{
		addr:    addr,
		handler: handler,
		logger:  logger,
	}
}

// Start begins listening for incoming UDP probes
func (s *Server) Start() error {
	s.logger.Info("Starting UDP honeypot server on " + s.addr)

	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		s.logger.Error("Failed to resolve address: " + err.Error())
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		s.logger.Error("Failed to listen on UDP: " + err.Error())
		return err
	}
	defer conn.Close()

	buffer := make([]byte, 512)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			s.logger.Error("Error reading UDP packet: " + err.Error())
			continue
		}

		// Process the probe asynchronously
		go s.handleProbe(conn, remoteAddr, buffer[:n])
	}
}

// handleProbe processes an incoming probe
func (s *Server) handleProbe(conn *net.UDPConn, remoteAddr *net.UDPAddr, payload []byte) {
	response, err := s.handler.Handle(
		remoteAddr.IP.String(),
		remoteAddr.Port,
		"UDP",
		string(payload),
	)

	if err != nil {
		s.logger.Error("Error processing probe: " + err.Error())
		return
	}

	// Send response if one was generated
	if response != "" {
		_, err := conn.WriteToUDP([]byte(response), remoteAddr)
		if err != nil {
			s.logger.Error("Error sending response: " + err.Error())
		}
	}
}
