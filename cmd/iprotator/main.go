package main

import (
	"bufio"
	"context"
	"flag"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"fmt"
	"strings"

	"iprotator/internal/config"
	"iprotator/internal/ippool"
	"iprotator/internal/logger"
	"iprotator/internal/network"
	"iprotator/internal/proxy"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		// If config not found, start interactive setup
		if os.IsNotExist(err) || strings.Contains(err.Error(), "config file not found") {
			fmt.Println("Config file not found. Starting interactive setup...")
			cfg = runInteractiveSetup(*configPath)
		} else {
			log.Fatalf("Failed to load configuration: %v", err)
		}
	}

	// Initialize logger
	logger.Init(cfg.Logging.Level)
	logger.Info("Configuration loaded successfully")
	logger.Info("Log level: %s", cfg.Logging.Level)
	logger.Info("Listen port: %d", cfg.Server.ListenPort)
	logger.Info("Rotation strategy: %s (Sticky: %v)", cfg.Rotation.Strategy, cfg.Rotation.Sticky)

	// --- Automated IP Management ---

	// --- Automated IP Management ---

	// Create network manager
	var primaryIP string
	nm, err := network.NewManager(cfg.IPPool.Interface)
	if err != nil {
		logger.Error("Failed to initialize network manager: %v. Please ensure interface %s exists.", err, cfg.IPPool.Interface)
		// Proceed without management
	} else {
		// CRITICAL: managing IPs requires root privileges
		if os.Geteuid() != 0 {
			logger.Error("!!! WARNING !!! running without root privileges. IP management (flush/add) will likely fail.")
			logger.Error("Please run with sudo: sudo ./iprotator-linux-amd64 ...")
		}

		// 1. Detect Primary IP
		var pErr error
		// Strategy:
		// 1. Configured PrimaryIP (highest priority)
		// 2. GetOutboundIP() (UDP dial, very reliable for main interface)
		// 3. GetPrimaryIP() (Route parsing, fallback)

		if cfg.IPPool.PrimaryIP != "" {
			primaryIP = cfg.IPPool.PrimaryIP
			logger.Info("Using configured Primary IP: %s", primaryIP)
		} else {
			// Try UDP dial first
			outboundIP, err := network.GetOutboundIP()
			if err == nil && outboundIP != "" {
				primaryIP = outboundIP
				logger.Info("Detected outbound IP (via UDP): %s", primaryIP)
			} else {
				// Fallback to route parsing
				logger.Warn("Failed to detect outbound IP: %v. Falling back to route parsing.", err)
				primaryIP, pErr = nm.GetPrimaryIP()
				if pErr != nil {
					logger.Warn("Failed to detect primary IP from routes: %v", pErr)

					// Last resort: Gateway
					if cfg.IPPool.Gateway != "" {
						logger.Info("Using configured Gateway IP as fallback safe IP: %s", cfg.IPPool.Gateway)
						primaryIP = cfg.IPPool.Gateway
					} else {
						logger.Warn("No primary IP detected. Skipping flush for safety.")
					}
				} else {
					logger.Info("Detected primary IP from routes: %s", primaryIP)
				}
			}
		}

		// 2. Flush existing IPs (excluding primary)
		// Only if we found a safe IP
		if primaryIP != "" {
			logger.Info("Flushing secondary IPs from interface %s...", cfg.IPPool.Interface)
			if err := nm.FlushSecondaryIPs(primaryIP); err != nil {
				logger.Error("Failed to flush IPs: %v", err)
			}
		}
	}

	// Convert config ranges to ippool ranges
	ranges := make([]ippool.IPRange, len(cfg.IPPool.Ranges))
	for i, r := range cfg.IPPool.Ranges {
		ranges[i] = ippool.IPRange{
			Start: r.Start,
			End:   r.End,
		}
	}

	// Create IP pool
	pool, err := ippool.NewPool(
		cfg.IPPool.Addresses,
		ranges,
		cfg.IPPool.Subnets,
		cfg.IPPool.Gateway,
		cfg.Rotation.Strategy,
		cfg.Rotation.Sticky,
	)
	if err != nil {
		log.Fatalf("Failed to create IP pool: %v", err)
	}

	logger.Info("IP pool initialized with %d addresses", pool.Size())
	if pool.HasGateway() {
		logger.Info("Gateway: %s", pool.Gateway().String())
	}

	// Add IPs to interface if manager is available
	if nm != nil {
		logger.Info("Assigning %d IPs to interface %s...", pool.Size(), cfg.IPPool.Interface)
		count := 0
		for _, ip := range pool.GetAddresses() {
			if err := nm.AddIP(ip); err != nil {
				logger.Warn("Failed to assign IP %s: %v", ip.String(), err)
			} else {
				count++
			}
		}
		logger.Info("Successfully assigned %d IPs", count)

		// Verify IPs are actually bound
		if count > 0 {
			logger.Info("Verifying IP assignments...")
			// Sleep briefly to allow DAD (Duplicate Address Detection) to settle
			time.Sleep(500 * time.Millisecond)

			finalAddrs, err := nm.ListIPs() // Need to implement this or just use AddrList
			if err != nil {
				logger.Warn("Failed to list IPs for verification: %v", err)
			} else {
				// Simple check
				for _, ip := range pool.GetAddresses() {
					found := false
					for _, addr := range finalAddrs {
						if addr.Equal(ip) {
							found = true
							break
						}
					}
					if !found {
						logger.Error("!!! CRITICAL: IP %s was assigned but not found on interface! Bind will fail.", ip.String())
					}
				}
			}
		}
	}

	// Create and start proxy server
	logger.Info("DNS servers: %v", cfg.DNS.Servers)
	logger.Info("DNS cache TTL: %d seconds", cfg.DNS.CacheTTL)

	if cfg.Server.Username != "" {
		logger.Info("Proxy Authentication ENABLED. Username: %s", cfg.Server.Username)
	} else {
		logger.Info("Proxy Authentication DISABLED (Open Proxy)")
	}

	server := proxy.NewServer(cfg.Server.ListenPort, pool, cfg.DNS.Servers, cfg.DNS.CacheTTL, cfg.Server.Username, cfg.Server.Password)

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		logger.Info("Received shutdown signal")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Logic for shutdown cleanup
		if nm != nil && primaryIP != "" {
			logger.Info("Cleaning up: removing secondary IPs from interface %s...", cfg.IPPool.Interface)
			if err := nm.FlushSecondaryIPs(primaryIP); err != nil {
				logger.Error("Failed to cleanup IPs: %v", err)
			} else {
				logger.Info("Cleanup successful. Secondary IPs removed.")
			}
		}

		if err := server.Shutdown(ctx); err != nil {
			logger.Error("Error during shutdown: %v", err)
		}
	}()

	// Start the server
	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}

	logger.Info("Server stopped gracefully")
}

func runInteractiveSetup(configPath string) *config.Config {
	reader := bufio.NewReader(os.Stdin)
	cfg := config.DefaultConfig()

	// 1. Detect and ask for Interface
	defaultIface, err := network.DetectDefaultInterface()
	if err != nil {
		fmt.Printf("Could not auto-detect default interface: %v\n", err)
		defaultIface = "eth0"
	} else {
		fmt.Printf("Auto-detected default interface: %s\n", defaultIface)
	}
	cfg.IPPool.Interface = promptString(reader, fmt.Sprintf("Network Interface [%s]: ", defaultIface), defaultIface)

	// 2. Detect and ask for Gateway and Primary IP
	var defaultGw string
	var defaultPrimary string

	nm, err := network.NewManager(cfg.IPPool.Interface)
	if err == nil {
		if gw, err := nm.GetPrimaryIP(); err == nil {
			defaultGw = gw
		}
		// Try to detect actual machine IP for primary_ip
		if ip, err := network.GetOutboundIP(); err == nil {
			defaultPrimary = ip
		}
	} else {
		fmt.Printf("Network manager init failed during setup: %v\n", err)
	}

	if defaultPrimary != "" {
		fmt.Printf("Auto-detected Machine Primary IP: %s\n", defaultPrimary)
	}
	cfg.IPPool.PrimaryIP = promptString(reader, fmt.Sprintf("Machine Primary IP (IMPORTANT: kept during flush) [%s]: ", defaultPrimary), defaultPrimary)

	cfg.IPPool.Gateway = promptString(reader, fmt.Sprintf("Gateway IP (usually router IP) [%s]: ", defaultGw), defaultGw)

	// 3. Ask for Port
	cfg.Server.ListenPort = promptInt(reader, fmt.Sprintf("Listen Port [%d]: ", cfg.Server.ListenPort), cfg.Server.ListenPort)

	// 3.5 Authentication
	fmt.Println("\n--- Proxy Authentication ---")
	userResp := promptString(reader, "Enter Username (leave empty for no auth): ", "")
	if userResp != "" {
		cfg.Server.Username = userResp
		passResp := promptString(reader, "Enter Password (leave empty to generate random): ", "")
		if passResp == "" {
			// Generate random password
			newPass := generateRandomPassword(12)
			fmt.Printf("GENERATED PASSWORD: %s\n", newPass)
			fmt.Println("Start the server to use these credentials.")
			cfg.Server.Password = newPass
		} else {
			cfg.Server.Password = passResp
		}
	}

	// 4. IP Addresses (Menu loop)
	for {
		fmt.Printf("\n--- IP Configuration (Total IPs: %d) ---\n",
			len(cfg.IPPool.Addresses)+len(cfg.IPPool.Ranges)+len(cfg.IPPool.Subnets))
		fmt.Println("1. Add IP Range (Start - End)")
		fmt.Println("2. Add Subnet (CIDR)")
		fmt.Println("3. Add Single IP(s)")
		fmt.Println("4. Done / Continue")

		choice := promptString(reader, "Choose option [4]: ", "4")

		switch choice {
		case "1":
			fmt.Println("Enter IP Range:")
			start := promptString(reader, "  Start IP: ", "")
			if start != "" {
				end := promptString(reader, "  End IP: ", "")
				if end != "" {
					cfg.IPPool.Ranges = append(cfg.IPPool.Ranges, config.IPRange{Start: start, End: end})
					fmt.Println("  -> Range added.")
				}
			}
		case "2":
			subnet := promptString(reader, "Enter Subnet (e.g. 192.168.1.0/24): ", "")
			if subnet != "" {
				cfg.IPPool.Subnets = append(cfg.IPPool.Subnets, subnet)
				fmt.Println("  -> Subnet added.")
			}
		case "3":
			ips := promptString(reader, "Enter IP Address(es) (comma separated): ", "")
			if ips != "" {
				parts := strings.Split(ips, ",")
				count := 0
				for _, p := range parts {
					p = strings.TrimSpace(p)
					if p != "" {
						cfg.IPPool.Addresses = append(cfg.IPPool.Addresses, p)
						count++
					}
				}
				fmt.Printf("  -> %d IP(s) added.\n", count)
			}
		case "4":
			// Validate at least one IP source exists
			if len(cfg.IPPool.Addresses) == 0 && len(cfg.IPPool.Ranges) == 0 && len(cfg.IPPool.Subnets) == 0 {
				fmt.Println("Error: You must add at least one IP address, range, or subnet.")
				continue
			}
			goto LoopEnd
		default:
			fmt.Println("Invalid choice.")
		}
	}
LoopEnd:

	// 5. DNS
	fmt.Println("\n--- DNS Configuration ---")
	dns := promptString(reader, "DNS Servers (comma separated) [1.1.1.1,8.8.8.8]: ", "1.1.1.1,8.8.8.8")
	parts := strings.Split(dns, ",")
	cfg.DNS.Servers = []string{}
	for _, p := range parts {
		cfg.DNS.Servers = append(cfg.DNS.Servers, strings.TrimSpace(p))
	}

	// 6. Logging & Rotation
	cfg.Rotation.Sticky = promptString(reader, "Enable Sticky Sessions (keep same IP for same host)? (y/N) [N]: ", "N") == "y"
	cfg.Logging.Level = promptString(reader, "Log Level (debug, info, warn, error) [info]: ", "info")

	// Save
	if err := config.CreateDefaultConfigFile(configPath, cfg); err != nil {
		fmt.Printf("Failed to save config file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Configuration saved to %s\n\n", configPath)

	return cfg
}

func promptString(reader *bufio.Reader, prompt string, defaultVal string) string {
	fmt.Print(prompt)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return defaultVal
	}
	return text
}

func promptInt(reader *bufio.Reader, prompt string, defaultVal int) int {
	fmt.Print(prompt)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(text)
	if err != nil {
		fmt.Printf("Invalid number, using default: %d\n", defaultVal)
		return defaultVal
	}
	return val
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generateRandomPassword(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
