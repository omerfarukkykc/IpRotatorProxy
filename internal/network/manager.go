package network

import (
	"fmt"
	"net"

	"syscall"

	"iprotator/internal/logger"

	"github.com/vishvananda/netlink"
)

// Manager handles network interface and IP address operations
type Manager struct {
	link netlink.Link
}

// NewManager creates a new network manager for the specified interface
func NewManager(interfaceName string) (*Manager, error) {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", interfaceName, err)
	}
	return &Manager{link: link}, nil
}

// GetOutboundIP gets the preferred outbound ip of this machine
// It uses a UDP connection to determine the local IP used for routing
func GetOutboundIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.String(), nil
}

// DetectDefaultInterface attempts to find the network interface with the default route
func DetectDefaultInterface() (string, error) {
	// List all routes from all interfaces
	// RouteList with nil link returns all
	routes, err := netlink.RouteList(nil, syscall.AF_INET)
	if err != nil {
		return "", fmt.Errorf("failed to list routes: %w", err)
	}

	for _, route := range routes {
		// Default route usually has Dst == nil or Dst.IP == nil/0.0.0.0
		// Also verify it has a gateway
		if route.Dst == nil || route.Dst.IP.Equal(net.IPv4zero) {
			if route.LinkIndex > 0 {
				link, err := netlink.LinkByIndex(route.LinkIndex)
				if err != nil {
					continue
				}
				// Skip loopback just in case
				if link.Attrs().Flags&net.FlagLoopback != 0 {
					continue
				}
				return link.Attrs().Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface with default route found")
}

// GetPrimaryIP attempts to find the primary IP address of the interface
// It checks existing routes to find the source IP for the default gateway
func (m *Manager) GetPrimaryIP() (string, error) {
	// 1. Check routes for default gateway
	routes, err := netlink.RouteList(m.link, syscall.AF_INET)
	if err != nil {
		return "", err
	}

	for _, route := range routes {
		// Default route usually has Dst == nil or Dst.IP == nil/0.0.0.0
		if route.Dst == nil || route.Dst.IP.Equal(net.IPv4zero) {
			if route.Src != nil {
				return route.Src.String(), nil
			}
		}
	}

	// Fallback: iterate over addresses and pick the first non-loopback?
	// This might be risky if we pick a secondary IP
	// But usually primary IP is added first.
	return "", fmt.Errorf("could not determine primary IP from routes")
}

// FlushSecondaryIPs removes all secondary IP addresses from the interface
// It preserves the primary IP.
// WARN: This is a destructive operation.
func (m *Manager) FlushSecondaryIPs(safeIP string) error {
	addrs, err := netlink.AddrList(m.link, syscall.AF_INET)
	if err != nil {
		return fmt.Errorf("failed to list addresses: %w", err)
	}

	for _, addr := range addrs {
		ipStr := addr.IP.String()

		// Skip loopback
		if addr.IP.IsLoopback() {
			continue
		}

		// Skip safe/primary IP
		if safeIP != "" && ipStr == safeIP {
			logger.Info("Skipping primary IP: %s", ipStr)
			continue
		}

		logger.Info("Removing IP: %s from %s", ipStr, m.link.Attrs().Name)
		if err := netlink.AddrDel(m.link, &addr); err != nil {
			logger.Warn("Failed to remove IP %s: %v", ipStr, err)
			continue
		}
	}
	return nil
}

// AddIP adds a secondary IP address to the interface
func (m *Manager) AddIP(ip net.IP) error {
	// Add with /32 mask for individual static IPs usually
	// Or should we use the mask from config?
	// For proxy rotation, /32 is standard for alias IPs.
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		},
	}

	// Check if exists
	// This check is implicit in AddrAdd usually returning error, but good to be clean

	if err := netlink.AddrAdd(m.link, addr); err != nil {
		// Ignore "file exists" error (IP already assigned)
		if err.Error() == "file exists" {
			return nil
		}
		return fmt.Errorf("failed to add IP %s: %w", ip.String(), err)
	}

	logger.Debug("Added IP: %s to %s", ip.String(), m.link.Attrs().Name)
	return nil
}

// ListIPs returns all IP addresses currently assigned to the interface
func (m *Manager) ListIPs() ([]net.IP, error) {
	addrs, err := netlink.AddrList(m.link, syscall.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses: %w", err)
	}

	var ips []net.IP
	for _, addr := range addrs {
		ips = append(ips, addr.IP)
	}
	return ips, nil
}
