package servers

import (
	"context"
	"net"

	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/handlers"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
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

// Start begins listening for incoming UDP probes.
// It returns when ctx is cancelled or a fatal socket error occurs.
func (s *Server) Start(ctx context.Context) error {
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

	// Close the connection when the context is cancelled so ReadFromUDP unblocks.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buffer := make([]byte, 512)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown via context cancellation
			}
			s.logger.Error("Error reading UDP packet: " + err.Error())
			continue
		}

		// Copy the payload before spawning the goroutine so the buffer can be reused.
		data := make([]byte, n)
		copy(data, buffer[:n])
		go s.handleProbe(conn, remoteAddr, data)
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
