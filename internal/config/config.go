package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	IPPool   IPPoolConfig   `yaml:"ip_pool"`
	Rotation RotationConfig `yaml:"rotation"`
	DNS      DNSConfig      `yaml:"dns"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ServerConfig holds server-related settings
type ServerConfig struct {
	ListenPort int    `yaml:"listen_port"`
	Username   string `yaml:"username"` // Proxy Basic Auth Username
	Password   string `yaml:"password"` // Proxy Basic Auth Password
}

// IPPoolConfig holds IP pool configuration
type IPPoolConfig struct {
	Interface string    `yaml:"interface"` // Network interface name (e.g. eth0)
	Addresses []string  `yaml:"addresses"`
	Ranges    []IPRange `yaml:"ranges"`
	Subnets   []string  `yaml:"subnets"`    // CIDR notation, e.g., "192.168.1.0/24"
	Gateway   string    `yaml:"gateway"`    // Gateway IP for routing
	PrimaryIP string    `yaml:"primary_ip"` // Explicitly set the primary IP to preserve
}

// IPRange represents a range of IP addresses
type IPRange struct {
	Start string `yaml:"start"`
	End   string `yaml:"end"`
}

// RotationConfig holds IP rotation settings
type RotationConfig struct {
	Strategy string `yaml:"strategy"` // "round-robin" or "random"
	Sticky   bool   `yaml:"sticky"`   // true to assign sticky IPs per host
}

// DNSConfig holds DNS resolver settings
type DNSConfig struct {
	Servers  []string `yaml:"servers"`   // DNS server addresses (e.g., "1.1.1.1", "8.8.8.8")
	CacheTTL int      `yaml:"cache_ttl"` // DNS cache TTL in seconds
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level string `yaml:"level"` // "debug", "info", "warn", "error", "none"
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			ListenPort: 8080,
		},
		IPPool: IPPoolConfig{
			Interface: "eth0", // Default interface
			Addresses: []string{},
			Ranges:    []IPRange{},
			Subnets:   []string{},
			Gateway:   "",
		},
		Rotation: RotationConfig{
			Strategy: "round-robin",
		},
		DNS: DNSConfig{
			Servers:  []string{"1.1.1.1", "8.8.8.8", "8.8.4.4"},
			CacheTTL: 300, // 5 minutes
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}

// LoadFromFile loads configuration from a YAML file
func LoadFromFile(path string) (*Config, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// CreateDefaultConfigFile creates a config file with provided values or defaults
func CreateDefaultConfigFile(path string, cfg *Config) error {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Add comments manually or use a template (simple marshal loses comments)
	// For now, let's use the struct and marshal it, users can edit later.
	// Recreating the string with comments with inserted values is better for UX.

	defaultContent := fmt.Sprintf(`# IP Rotator Proxy Server Configuration
# Auto-generated configuration

server:
  # Port to listen on for incoming proxy requests
  listen_port: %d
  
  # Basic Authentication (Leave empty to disable)
  # username: "admin"
  # password: "securepassword"
  username: "%s"
  password: "%s"

ip_pool:
  # Network interface to manage (e.g., eth0, ens192)
  interface: "%s"

  # Single IP addresses
  addresses:`, cfg.Server.ListenPort, cfg.Server.Username, cfg.Server.Password, cfg.IPPool.Interface)

	if len(cfg.IPPool.Addresses) > 0 {
		for _, addr := range cfg.IPPool.Addresses {
			defaultContent += fmt.Sprintf("\n    - \"%s\"", addr)
		}
	} else {
		defaultContent += "\n    # - \"192.168.1.10\""
	}

	defaultContent += `
  
  # IP ranges (all IPs from start to end inclusive)
  ranges:`

	if len(cfg.IPPool.Ranges) > 0 {
		for _, r := range cfg.IPPool.Ranges {
			defaultContent += fmt.Sprintf("\n    - start: \"%s\"\n      end: \"%s\"", r.Start, r.End)
		}
	} else {
		defaultContent += `
  #   - start: "192.168.1.100"
  #     end: "192.168.1.110"`
	}

	defaultContent += `
  
  # Subnets in CIDR notation
  subnets:`

	if len(cfg.IPPool.Subnets) > 0 {
		for _, s := range cfg.IPPool.Subnets {
			defaultContent += fmt.Sprintf("\n    - \"%s\"", s)
		}
	} else {
		defaultContent += `
  #   - "192.168.1.0/28"`
	}

	defaultContent += `
  
  # Gateway IP for routing
  gateway: "` + cfg.IPPool.Gateway + `"
  
  # Explicitly set your main/management IP to preserve it during flushing
  # primary_ip: "` + cfg.IPPool.PrimaryIP + `"`

	defaultContent += fmt.Sprintf(`

rotation:
  # IP rotation strategy: "round-robin" or "random"
  strategy: "%s"

  # Sticky sessions: keep using same IP for same host (true/false)
  # Default is false (rotate on every request)
  sticky: %v

dns:
  # DNS servers to use for resolution (in order of preference)
  servers:`, cfg.Rotation.Strategy, cfg.Rotation.Sticky)

	for _, s := range cfg.DNS.Servers {
		defaultContent += fmt.Sprintf("\n    - \"%s\"", s)
	}

	defaultContent += fmt.Sprintf(`
  
  # DNS cache TTL in seconds (default: 300 = 5 minutes)
  cache_ttl: %d

logging:
  # Log level: "debug", "info", "warn", "error", "none"
  level: "%s"
`, cfg.DNS.CacheTTL, cfg.Logging.Level)

	return os.WriteFile(path, []byte(defaultContent), 0644)
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Server.ListenPort < 1 || c.Server.ListenPort > 65535 {
		return fmt.Errorf("listen_port must be between 1 and 65535")
	}

	if c.IPPool.Interface == "" {
		return fmt.Errorf("ip_pool.interface must be specified")
	}

	if len(c.IPPool.Addresses) == 0 && len(c.IPPool.Ranges) == 0 && len(c.IPPool.Subnets) == 0 {
		return fmt.Errorf("at least one IP address, range, or subnet must be specified")
	}

	if c.Rotation.Strategy != "round-robin" && c.Rotation.Strategy != "random" {
		return fmt.Errorf("rotation strategy must be 'round-robin' or 'random'")
	}

	if len(c.DNS.Servers) == 0 {
		return fmt.Errorf("at least one DNS server must be specified")
	}

	if c.DNS.CacheTTL < 0 {
		return fmt.Errorf("dns cache_ttl must be non-negative")
	}

	return nil
}
