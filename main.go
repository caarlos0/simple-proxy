package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type hostBlocklist map[string]struct{}

func loadBlocklist(path string) (hostBlocklist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read blocklist: %w", err)
	}

	blocklist := make(hostBlocklist)
	for index, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		host := normalizeHost(line)
		_, isIP := canonicalIP(host)
		if host == "" ||
			!isASCII(host) ||
			strings.ContainsAny(host, " \t\r\n/\\*") ||
			(strings.Contains(host, ":") && !isIP) {
			return nil, fmt.Errorf("%s:%d: invalid host %q", path, index+1, line)
		}
		blocklist[host] = struct{}{}
	}

	return blocklist, nil
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	host = strings.TrimRight(strings.ToLower(host), ".")
	if address, ok := canonicalIP(host); ok {
		return address
	}
	return host
}

func canonicalIP(host string) (string, bool) {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String(), true
	}

	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return "", false
	}

	var octets [4]byte
	for index, part := range parts {
		value, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return "", false
		}
		octets[index] = byte(value)
	}
	return netip.AddrFrom4(octets).String(), true
}

func isASCII(value string) bool {
	for _, character := range value {
		if character > 127 {
			return false
		}
	}
	return true
}

func (b hostBlocklist) blocks(host string) bool {
	host = normalizeHost(host)
	if _, blocked := b[host]; blocked {
		return true
	}
	if _, isIP := canonicalIP(host); isIP {
		return false
	}

	for {
		dot := strings.IndexByte(host, '.')
		if dot < 0 {
			return false
		}
		host = host[dot+1:]
		if _, isIP := canonicalIP(host); isIP {
			return false
		}
		if _, blocked := b[host]; blocked {
			return true
		}
	}
}

type proxy struct {
	blocklist hostBlocklist
	transport *http.Transport
	dialer    *net.Dialer
	logger    *slog.Logger
}

func newProxy(blocklist hostBlocklist, logger *slog.Logger) *proxy {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true

	return &proxy{
		blocklist: blocklist,
		transport: transport,
		dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		logger: logger,
	}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, err := destinationHost(r)
	if err != nil {
		p.logRequest(r, "", "rejected")
		p.logger.Warn("invalid proxy request", "error", err)
		http.Error(w, "invalid proxy target", http.StatusBadRequest)
		return
	}

	action := "allowed"
	if p.blocklist.blocks(host) {
		action = "blocked"
	}
	p.logRequest(r, host, action)

	if action == "blocked" {
		http.Error(w, "host blocked by proxy", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodConnect {
		p.tunnelHTTPS(w, r)
		return
	}
	p.forwardHTTP(w, r)
}

func destinationHost(r *http.Request) (string, error) {
	if r.Method == http.MethodConnect {
		host, port, err := net.SplitHostPort(r.Host)
		if err != nil || host == "" || port == "" {
			return "", fmt.Errorf("CONNECT target must be host:port")
		}
		host = normalizeHost(host)
		if !isASCII(host) {
			return "", fmt.Errorf("CONNECT host must use ASCII or Punycode")
		}
		return host, nil
	}

	scheme := strings.ToLower(r.URL.Scheme)
	if scheme != "http" || r.URL.Host == "" {
		return "", fmt.Errorf("request URL must be absolute HTTP")
	}
	host := normalizeHost(r.URL.Hostname())
	if !isASCII(host) {
		return "", fmt.Errorf("request host must use ASCII or Punycode")
	}
	return host, nil
}

func (p *proxy) logRequest(r *http.Request, host, action string) {
	target := r.Host
	if r.Method != http.MethodConnect {
		path := r.URL.EscapedPath()
		if path == "" {
			path = "/"
		}
		target = r.URL.Scheme + "://" + r.URL.Host + path
	}

	p.logger.Info(
		"request",
		"remote", r.RemoteAddr,
		"method", r.Method,
		"host", host,
		"target", target,
		"action", action,
	)
}

func (p *proxy) forwardHTTP(w http.ResponseWriter, r *http.Request) {
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Host = r.URL.Host
	removeHopByHopHeaders(out.Header)

	response, err := p.transport.RoundTrip(out)
	if err != nil {
		p.logger.Error("forward request failed", "host", r.URL.Host, "error", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}

	removeHopByHopHeaders(response.Header)
	for name, values := range response.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.StatusCode)

	_, copyErr := io.Copy(w, response.Body)
	closeErr := response.Body.Close()
	if copyErr != nil {
		p.logger.Warn("forward response interrupted", "host", r.URL.Host, "error", copyErr)
	}
	if closeErr != nil {
		p.logger.Warn("close upstream response", "host", r.URL.Host, "error", closeErr)
	}
}

func removeHopByHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}

	for _, name := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
}

func (p *proxy) tunnelHTTPS(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connection tunneling is unavailable", http.StatusInternalServerError)
		return
	}

	upstream, err := p.dialer.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		p.logger.Error("connect to upstream failed", "host", r.Host, "error", err)
		http.Error(w, "upstream connection failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	client, buffered, err := hijacker.Hijack()
	if err != nil {
		p.logger.Error("hijack client connection", "error", err)
		return
	}
	defer client.Close()

	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		p.logger.Warn("write CONNECT response", "error", err)
		return
	}
	if err := buffered.Flush(); err != nil {
		p.logger.Warn("flush CONNECT response", "error", err)
		return
	}

	copyErrors := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, buffered)
		copyErrors <- err
	}()
	go func() {
		_, err := io.Copy(client, upstream)
		copyErrors <- err
	}()

	if err := <-copyErrors; err != nil && !errors.Is(err, net.ErrClosed) {
		p.logger.Warn("tunnel interrupted", "host", r.Host, "error", err)
	}
}

func main() {
	listenAddress := flag.String("listen", "127.0.0.1:8080", "address to listen on")
	blocklistPath := flag.String("blocklist", "blocklist.txt", "path to the host blocklist")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	blocklist, err := loadBlocklist(*blocklistPath)
	if err != nil {
		logger.Error("load blocklist", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              *listenAddress,
		Handler:           newProxy(blocklist, logger),
		ReadHeaderTimeout: 10 * time.Second,
	}
	logger.Info(
		"proxy listening",
		"address", *listenAddress,
		"blocklist", *blocklistPath,
		"blocked_hosts", len(blocklist),
	)
	if err := server.ListenAndServe(); err != nil {
		logger.Error("proxy stopped", "error", err)
		os.Exit(1)
	}
}
