package ippool

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

// Pool manages a collection of IP addresses for rotation
type Pool struct {
	addresses []net.IP
	gateway   net.IP
	index     int
	strategy  string
	mu        sync.Mutex
	rng       *rand.Rand
	sticky    bool // Enable sticky sessions
	// Sticky IP map: host -> {ip, expiration}
	stickyIPs map[string]stickyEntry
}

type stickyEntry struct {
	ip        net.IP
	expiresAt time.Time
}

// NewPool creates a new IP pool from addresses, ranges, and subnets
func NewPool(addresses []string, ranges []IPRange, subnets []string, gateway string, strategy string, sticky bool) (*Pool, error) {
	pool := &Pool{
		addresses: make([]net.IP, 0),
		index:     0,
		strategy:  strategy,
		sticky:    sticky,
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
		stickyIPs: make(map[string]stickyEntry),
	}

	// Parse gateway if specified
	if gateway != "" {
		gw := net.ParseIP(gateway)
		if gw == nil {
			return nil, fmt.Errorf("invalid gateway IP: %s", gateway)
		}
		pool.gateway = gw
	}

	// Parse single IP addresses
	for _, addr := range addresses {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", addr)
		}
		pool.addresses = append(pool.addresses, ip)
	}

	// Parse IP ranges
	for _, r := range ranges {
		ips, err := parseIPRange(r.Start, r.End)
		if err != nil {
			return nil, fmt.Errorf("invalid IP range %s-%s: %w", r.Start, r.End, err)
		}
		pool.addresses = append(pool.addresses, ips...)
	}

	// Parse subnets (CIDR notation)
	for _, subnet := range subnets {
		ips, err := parseSubnet(subnet)
		if err != nil {
			return nil, fmt.Errorf("invalid subnet %s: %w", subnet, err)
		}
		pool.addresses = append(pool.addresses, ips...)
	}

	if len(pool.addresses) == 0 {
		return nil, fmt.Errorf("no valid IP addresses in pool")
	}

	// Start cleanup routine
	go pool.cleanupStickyIPs()

	return pool, nil
}

// IPRange represents a range of IP addresses
type IPRange struct {
	Start string
	End   string
}

// Next selects an IP address. If host is provided, it tries to use stickiness.
func (p *Pool) Next(host string) net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check sticky map first (if enabled)
	if p.sticky && host != "" {
		if entry, ok := p.stickyIPs[host]; ok {
			if time.Now().Before(entry.expiresAt) {
				return entry.ip
			}
			// Expired
			delete(p.stickyIPs, host)
		}
	}

	var ip net.IP
	switch p.strategy {
	case "random":
		idx := p.rng.Intn(len(p.addresses))
		ip = p.addresses[idx]
	default: // round-robin
		ip = p.addresses[p.index]
		p.index = (p.index + 1) % len(p.addresses)
	}

	// Save sticky IP (if enabled)
	if p.sticky && host != "" {
		p.stickyIPs[host] = stickyEntry{
			ip:        ip,
			expiresAt: time.Now().Add(10 * time.Minute), // Default 10 min sticky
		}
	}

	return ip
}

func (p *Pool) cleanupStickyIPs() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		p.mu.Lock()
		now := time.Now()
		for host, entry := range p.stickyIPs {
			if now.After(entry.expiresAt) {
				delete(p.stickyIPs, host)
			}
		}
		p.mu.Unlock()
	}
}

// Size returns the number of IP addresses in the pool
func (p *Pool) Size() int {
	return len(p.addresses)
}

// GetAddresses returns all IP addresses in the pool
func (p *Pool) GetAddresses() []net.IP {
	result := make([]net.IP, len(p.addresses))
	copy(result, p.addresses)
	return result
}

// Gateway returns the configured gateway IP
func (p *Pool) Gateway() net.IP {
	return p.gateway
}

// HasGateway returns true if a gateway is configured
func (p *Pool) HasGateway() bool {
	return p.gateway != nil
}

// parseSubnet parses a CIDR subnet and returns all usable host IPs
func parseSubnet(cidr string) ([]net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %w", err)
	}

	// Only support IPv4
	if ipNet.IP.To4() == nil {
		return nil, fmt.Errorf("only IPv4 subnets are supported")
	}

	// Calculate the range of usable IPs (excluding network and broadcast)
	mask := ipNet.Mask
	ones, bits := mask.Size()
	hostBits := bits - ones

	// For /31 and /32, include all IPs
	// For larger subnets, exclude network and broadcast addresses
	networkIP := ipToUint32(ipNet.IP.To4())
	numHosts := uint32(1 << hostBits)

	// Limit subnet size to prevent memory issues
	if numHosts > 1024 {
		return nil, fmt.Errorf("subnet too large (max /22 or 1024 addresses)")
	}

	var ips []net.IP

	if hostBits <= 1 {
		// /31 or /32 - include all IPs
		for i := uint32(0); i < numHosts; i++ {
			ips = append(ips, uint32ToIP(networkIP+i))
		}
	} else {
		// Skip network address (first) and broadcast (last)
		for i := uint32(1); i < numHosts-1; i++ {
			ips = append(ips, uint32ToIP(networkIP+i))
		}
	}

	return ips, nil
}

// parseIPRange generates a list of IPs from start to end (inclusive)
func parseIPRange(startStr, endStr string) ([]net.IP, error) {
	start := net.ParseIP(startStr)
	if start == nil {
		return nil, fmt.Errorf("invalid start IP: %s", startStr)
	}

	end := net.ParseIP(endStr)
	if end == nil {
		return nil, fmt.Errorf("invalid end IP: %s", endStr)
	}

	// Convert to IPv4 if possible
	start = start.To4()
	end = end.To4()
	if start == nil || end == nil {
		return nil, fmt.Errorf("only IPv4 ranges are supported")
	}

	startInt := ipToUint32(start)
	endInt := ipToUint32(end)

	if startInt > endInt {
		return nil, fmt.Errorf("start IP must be less than or equal to end IP")
	}

	// Limit range size to prevent memory issues
	if endInt-startInt > 1000 {
		return nil, fmt.Errorf("IP range too large (max 1000 addresses)")
	}

	var ips []net.IP
	for i := startInt; i <= endInt; i++ {
		ips = append(ips, uint32ToIP(i))
	}

	return ips, nil
}

// ipToUint32 converts an IPv4 address to a uint32
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32ToIP converts a uint32 to an IPv4 address
func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}
