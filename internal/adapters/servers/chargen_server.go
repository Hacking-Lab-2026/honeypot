package servers

import (
	"context"
	"net"

	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/handlers"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

// ChargenServer represents a UDP CHARGEN (RFC 864) honeypot server endpoint
type ChargenServer struct {
	addr    string
	handler *handlers.ChargenHandler
	logger  ports.Logger
}

// NewChargenServer creates a new CHARGEN UDP server
func NewChargenServer(addr string, handler *handlers.ChargenHandler, logger ports.Logger) *ChargenServer {
	return &ChargenServer{
		addr:    addr,
		handler: handler,
		logger:  logger,
	}
}

// Start begins listening for incoming UDP CHARGEN probes.
// It returns when ctx is cancelled or a fatal socket error occurs.
func (s *ChargenServer) Start(ctx context.Context) error {
	s.logger.Info("Starting CHARGEN honeypot server on " + s.addr)

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

// handleProbe processes an incoming CHARGEN probe
func (s *ChargenServer) handleProbe(conn *net.UDPConn, remoteAddr *net.UDPAddr, payload []byte) {
	response, err := s.handler.Handle(
		remoteAddr.IP.String(),
		remoteAddr.Port,
		"UDP",
		string(payload),
	)

	if err != nil {
		s.logger.Error("Error processing CHARGEN probe: " + err.Error())
		return
	}

	if response != "" {
		_, err := conn.WriteToUDP([]byte(response), remoteAddr)
		if err != nil {
			s.logger.Error("Error sending CHARGEN response: " + err.Error())
		}
	}
}
