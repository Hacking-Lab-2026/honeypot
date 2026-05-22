package models

import "time"

// ExperimentStatus represents the lifecycle state of an experiment.
type ExperimentStatus string

const (
	StatusActive  ExperimentStatus = "active"
	StatusStopped ExperimentStatus = "stopped"
)

// AssignmentMode controls how incoming probes are mapped to experiment variants.
type AssignmentMode string

const (
	// AssignmentBySource uses a deterministic hash of (experimentID, sourceIP) — suitable for
	// single-IP honeypots where all traffic arrives on the same address.
	AssignmentBySource AssignmentMode = "source"
	// AssignmentByDestination maps each honeypot IP to a fixed variant via AssignedIPs — suitable
	// for multi-IP deployments where each IP represents a distinct treatment arm.
	AssignmentByDestination AssignmentMode = "destination"
)

// Experiment represents an A/B testing experiment.
type Experiment struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	Description    string           `json:"description"`
	Status         ExperimentStatus `json:"status"`
	AssignmentMode AssignmentMode   `json:"assignment_mode"`
	CreatedAt      time.Time        `json:"created_at"`
}

// Variant represents one arm of an experiment with its own per-protocol response config.
type Variant struct {
	ID           string    `json:"id"`
	ExperimentID string    `json:"experiment_id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	Weight       float64   `json:"weight"`                 // 0–1; source-mode variants must sum to 1.0
	AssignedIPs  []string  `json:"assigned_ips,omitempty"` // destination-mode: IPs that map to this variant
	DNSConfig    DNSConfig `json:"dns_config"`
	NTPConfig    NTPConfig `json:"ntp_config"`
}

// GetDNSConfig returns the DNS-specific configuration for this variant.
func (v *Variant) GetDNSConfig() DNSConfig { return v.DNSConfig }

// GetNTPConfig returns the NTP-specific configuration for this variant.
func (v *Variant) GetNTPConfig() NTPConfig { return v.NTPConfig }

// Assignment records which variant a source IP was assigned to (sticky per experiment).
type Assignment struct {
	SourceIP     string    `json:"source_ip"`
	ExperimentID string    `json:"experiment_id"`
	VariantID    string    `json:"variant_id"`
	AssignedAt   time.Time `json:"assigned_at"`
}
