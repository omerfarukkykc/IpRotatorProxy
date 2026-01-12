package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"iprotator/internal/ippool"
	"iprotator/internal/logger"
)

// DNSCache provides a simple DNS caching mechanism with custom resolver
type DNSCache struct {
	cache    map[string]*dnsCacheEntry
	mu       sync.RWMutex
	ttl      time.Duration
	resolver *net.Resolver
}

type dnsCacheEntry struct {
	ips       []net.IP
	expiresAt time.Time
}

// NewDNSCache creates a new DNS cache with custom DNS servers
func NewDNSCache(ttl time.Duration, servers []string) *DNSCache {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 3 * time.Second,
			}
			var lastErr error
			for _, server := range servers {
				// Add port if not specified
				if _, _, err := net.SplitHostPort(server); err != nil {
					server = server + ":53"
				}
				conn, err := d.DialContext(ctx, "udp", server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}

	return &DNSCache{
		cache:    make(map[string]*dnsCacheEntry),
		ttl:      ttl,
		resolver: resolver,
	}
}

// Lookup resolves a hostname, using cache if available
func (d *DNSCache) Lookup(host string) ([]net.IP, error) {
	// Check cache first
	d.mu.RLock()
	entry, ok := d.cache[host]
	if ok && time.Now().Before(entry.expiresAt) {
		d.mu.RUnlock()
		logger.Debug("DNS cache hit for %s", host)
		return entry.ips, nil
	}
	d.mu.RUnlock()

	// Resolve DNS using custom resolver
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		logger.Error("DNS lookup failed for %s: %v", host, err)
		return nil, err
	}

	ips := make([]net.IP, len(addrs))
	for i, addr := range addrs {
		ips[i] = addr.IP
	}

	// Cache the result
	d.mu.Lock()
	d.cache[host] = &dnsCacheEntry{
		ips:       ips,
		expiresAt: time.Now().Add(d.ttl),
	}
	d.mu.Unlock()

	logger.Debug("DNS resolved %s -> %v", host, ips[0])
	return ips, nil
}

// Server represents the HTTP proxy server
type Server struct {
	listenAddr string
	pool       *ippool.Pool
	server     *http.Server
	dnsCache   *DNSCache
	// Cache transports per IP for connection reuse
	transports   map[string]*http.Transport
	transportsMu sync.RWMutex
	// Basic Auth credentials (optional)
	username string
	password string
}

// NewServer creates a new proxy server
func NewServer(listenPort int, pool *ippool.Pool, dnsServers []string, dnsCacheTTL int, username, password string) *Server {
	ttl := time.Duration(dnsCacheTTL) * time.Second

	s := &Server{
		listenAddr: fmt.Sprintf(":%d", listenPort),
		pool:       pool,
		transports: make(map[string]*http.Transport),
		dnsCache:   NewDNSCache(ttl, dnsServers),
		username:   username,
		password:   password,
	}

	s.server = &http.Server{
		Addr:         s.listenAddr,
		Handler:      http.HandlerFunc(s.handleRequest),
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s
}

// Start starts the proxy server
func (s *Server) Start() error {
	logger.Info("Starting proxy server on %s", s.listenAddr)
	logger.Info("IP pool size: %d addresses", s.pool.Size())

	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// checkProxyAuth validates Proxy-Authorization header
func (s *Server) checkProxyAuth(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}

	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}

	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return false
	}

	cs := string(c)
	user, pass, ok := strings.Cut(cs, ":")
	if !ok {
		return false
	}

	return user == s.username && pass == s.password
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	logger.Info("Shutting down proxy server...")
	return s.server.Shutdown(ctx)
}

// handleRequest handles incoming proxy requests
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Check Basic Auth if configured
	if s.username != "" && s.password != "" {
		if !s.checkProxyAuth(r) {
			logger.Info("Proxy authentication failed from %s", r.RemoteAddr)
			w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Authentication Required"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}
	}

	host := r.Host
	// Remove port if present for sticky logic (so google.com:443 and google.com:80 use same IP)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	sourceIP := s.pool.Next(host)
	logger.Debug("%s %s -> using IP: %s (Sticky Host: %s)", r.Method, r.Host, sourceIP.String(), host)

	if r.Method == http.MethodConnect {
		s.handleHTTPS(w, r, sourceIP)
	} else {
		s.handleHTTP(w, r, sourceIP)
	}
}

// handleHTTP handles HTTP proxy requests
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request, sourceIP net.IP) {
	transport := s.getTransport(sourceIP)

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		logger.Error("HTTP forward failed for %s: %v", r.URL.Host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	buf := make([]byte, 32*1024)
	io.CopyBuffer(w, resp.Body, buf)
}

// handleHTTPS handles HTTPS CONNECT tunnel requests
func (s *Server) handleHTTPS(w http.ResponseWriter, r *http.Request, sourceIP net.IP) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = "443"
	}

	ips, err := s.dnsCache.Lookup(host)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	targetAddr := net.JoinHostPort(ips[0].String(), port)
	dialer := s.createDialer(sourceIP)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	targetConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		logger.Error("Connect failed to %s: %v", r.Host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		logger.Error("Hijack failed: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go s.copyAndClose(targetConn, clientConn)
	s.copyAndClose(clientConn, targetConn)
}

// copyAndClose copies data between connections and closes dst when done
func (s *Server) copyAndClose(dst, src net.Conn) {
	buf := make([]byte, 64*1024)
	io.CopyBuffer(dst, src, buf)
	dst.Close()
}

// getTransport gets or creates a cached transport for the given source IP
func (s *Server) getTransport(sourceIP net.IP) *http.Transport {
	key := sourceIP.String()

	s.transportsMu.RLock()
	if t, ok := s.transports[key]; ok {
		s.transportsMu.RUnlock()
		return t
	}
	s.transportsMu.RUnlock()

	s.transportsMu.Lock()
	defer s.transportsMu.Unlock()

	if t, ok := s.transports[key]; ok {
		return t
	}

	dialer := s.createDialerWithDNSCache(sourceIP)
	transport := &http.Transport{
		DialContext:           dialer,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    false,
		ForceAttemptHTTP2:     true,
	}

	s.transports[key] = transport
	return transport
}

// createDialerWithDNSCache creates a DialContext function that uses DNS cache
func (s *Server) createDialerWithDNSCache(sourceIP net.IP) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		ips, err := s.dnsCache.Lookup(host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed: %w", err)
		}

		dialer := &net.Dialer{
			LocalAddr: &net.TCPAddr{
				IP: sourceIP,
			},
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		resolvedAddr := net.JoinHostPort(ips[0].String(), port)
		return dialer.DialContext(ctx, network, resolvedAddr)
	}
}

// createDialer creates a net.Dialer bound to the given source IP
func (s *Server) createDialer(sourceIP net.IP) *net.Dialer {
	return &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP: sourceIP,
		},
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}
}
