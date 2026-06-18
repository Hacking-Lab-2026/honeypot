package services

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

// Service types a real UPnP device might advertise. Order is deterministic
// real ntpd-style honeypots could randomize this for plausibility
var fakeServiceTypes = []string{
	"upnp:rootdevice",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"urn:schemas-upnp-org:device:WANDevice:1",
	"urn:schemas-upnp-org:device:WANConnectionDevice:1",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1",
	"urn:schemas-upnp-org:service:Layer3Forwarding:1",
	"urn:schemas-upnp-org:device:Basic:1",
	"urn:schemas-upnp-org:device:MediaServer:1",
	"urn:schemas-upnp-org:service:ContentDirectory:1",
}

type SSDPService struct{}

// constructs SSDP replies based on the query and variant config
// "amplified": one HTTP 200 OK per advertised service (real UPnP amplification)
// anything else (including empty): single response advertising rootdevice only
// The fail-safe default is "minimal-like" behavior — amplification requires
// explicit opt-in via cfg.ResponseMode == "amplified"
func (s *SSDPService) BuildResponse(query *models.SSDPQuery, cfg models.SSDPConfig, localIP string) (models.SSDPResponse, error) {
	if cfg.ResponseMode != "amplified" {
		return s.buildMinimalResponse(query, localIP)
	}

	n := cfg.NumServices
	if n <= 0 {
		n = len(fakeServiceTypes)
	}
	if n > len(fakeServiceTypes) {
		n = len(fakeServiceTypes)
	}
	return s.buildAmplifiedResponse(query, n, localIP)
}

// returns a single response advertising only rootdevice
// Looks like a sparsely-configured UPnP device
func (s *SSDPService) buildMinimalResponse(query *models.SSDPQuery, localIP string) (models.SSDPResponse, error) {
	pkt := s.buildResponsePacket(query.ST, fakeServiceTypes[0], localIP)
	return models.SingleSSDPPacketResponse(pkt), nil
}

// returns N response packets, one per advertised service
func (s *SSDPService) buildAmplifiedResponse(query *models.SSDPQuery, numServices int, localIP string) (models.SSDPResponse, error) {
	packets := make([][]byte, 0, numServices)
	for i := 0; i < numServices; i++ {
		pkt := s.buildResponsePacket(query.ST, fakeServiceTypes[i], localIP)
		packets = append(packets, pkt)
	}
	return models.SSDPResponse{Packets: packets}, nil
}

// constructs a single HTTP 200 OK SSDP response
func (s *SSDPService) buildResponsePacket(requestST, serviceType, localIP string) []byte {
	now := time.Now().UTC().Format(time.RFC1123)
	uuid := generateUUID()

	// Echo back the request's ST if it's a specific target, otherwise use the
	// service type. Real UPnP behavior
	respST := serviceType
	if requestST != "" && requestST != "ssdp:all" && requestST != "upnp:rootdevice" {
		respST = requestST
	}

	body := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"CACHE-CONTROL: max-age=1800\r\n"+
			"DATE: %s\r\n"+
			"EXT:\r\n"+
			"LOCATION: http://%s:80/rootDesc.xml\r\n"+
			"SERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/1.9\r\n"+
			"ST: %s\r\n"+
			"USN: uuid:%s::%s\r\n"+
			"\r\n",
		now, localIP, respST, uuid, serviceType,
	)

	return []byte(body)
}

// returns a UUID v4 string. Non-cryptographic; just needs to look
// like a real UUID to a casual observer
func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}
