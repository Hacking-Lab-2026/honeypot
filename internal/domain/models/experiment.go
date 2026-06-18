package models

import "time"

type ExperimentStatus string

const (
	StatusActive  ExperimentStatus = "active"
	StatusStopped ExperimentStatus = "stopped"
)
type AssignmentMode string

const (
	AssignmentBySource AssignmentMode = "source"
	AssignmentByDestination AssignmentMode = "destination"
)

// represents an A/B testing experiment
type Experiment struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	Description    string           `json:"description"`
	Status         ExperimentStatus `json:"status"`
	AssignmentMode AssignmentMode   `json:"assignment_mode"`
	CreatedAt      time.Time        `json:"created_at"`
}

// represents one arm of an experiment with its own per-protocol response config
type Variant struct {
	ID           string     `json:"id"`
	ExperimentID string     `json:"experiment_id"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Weight       float64    `json:"weight"`                
	AssignedIPs  []string   `json:"assigned_ips,omitempty"` 
	DNSConfig    DNSConfig  `json:"dns_config"`
	NTPConfig    NTPConfig  `json:"ntp_config"`
	SSDPConfig   SSDPConfig `json:"ssdp_config"`
}

// DNS
func (v *Variant) GetDNSConfig() DNSConfig { return v.DNSConfig }

// NTP
func (v *Variant) GetNTPConfig() NTPConfig { return v.NTPConfig }

// SSDP
func (v *Variant) GetSSDPConfig() SSDPConfig { return v.SSDPConfig }


type Assignment struct {
	SourceIP     string    `json:"source_ip"`
	ExperimentID string    `json:"experiment_id"`
	VariantID    string    `json:"variant_id"`
	AssignedAt   time.Time `json:"assigned_at"`
}
