package servers

import (
	"context"
	"net"

	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/handlers"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

const dnsBufferSize = 512 // RFC 1035 Â§2.3.4 â€” standard DNS UDP payload limit

// DNSServer listens for UDP DNS queries on a single address and dispatches each packet to a goroutine.
type DNSServer struct {
	addr          string
	destinationIP string // the IP this server is bound to (used for destination-mode assignment)
	handler       *handlers.DNSHandler
	logger        ports.Logger
}

// NewDNSServer creates a new DNS honeypot server.
// destinationIP must be the IP portion of addr (e.g. "10.0.0.1" for addr "10.0.0.1:53").
func NewDNSServer(addr string, destinationIP string, handler *handlers.DNSHandler, logger ports.Logger) *DNSServer {
	return &DNSServer{
		addr:          addr,
		destinationIP: destinationIP,
		handler:       handler,
		logger:        logger,
	}
}

// Addr returns the listen address of this server.
func (s *DNSServer) Addr() string { return s.addr }

// Start begins listening for UDP DNS queries.
// It returns when ctx is cancelled or a fatal socket error occurs.
func (s *DNSServer) Start(ctx context.Context) error {
	s.logger.Info("Starting DNS honeypot server on " + s.addr)

	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		s.logger.Error("Failed to resolve DNS server address: " + err.Error())
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.logger.Error("Failed to listen on UDP for DNS: " + err.Error())
		return err
	}
	defer conn.Close()

	// Close the connection when the context is cancelled so ReadFromUDP unblocks.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buffer := make([]byte, dnsBufferSize)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown via context cancellation
			}
			s.logger.Error("Error reading DNS UDP packet: " + err.Error())
			continue
		}

		// Copy the payload before spawning the goroutine so the buffer can be reused.
		data := make([]byte, n)
		copy(data, buffer[:n])
		go s.handleQuery(conn, remoteAddr, data)
	}
}

func (s *DNSServer) handleQuery(conn *net.UDPConn, remoteAddr *net.UDPAddr, payload []byte) {
	response, err := s.handler.Handle(remoteAddr.IP.String(), remoteAddr.Port, s.destinationIP, payload)
	if err != nil {
		s.logger.Error("Error processing DNS query from " + remoteAddr.String() + ": " + err.Error())
		return
	}
	if len(response) > 0 {
		if _, err := conn.WriteToUDP(response, remoteAddr); err != nil {
			s.logger.Error("Error sending DNS response to " + remoteAddr.String() + ": " + err.Error())
		}
	}
}
