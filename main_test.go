package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadBlocklist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.txt")
	content := `
# comments and blank lines are ignored
Example.COM.
192.0.2.1 # inline comments are supported
::1
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	blocklist, err := loadBlocklist(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]bool{
		"example.com":         true,
		"api.example.com":     true,
		"notexample.com":      false,
		"192.0.2.1":           true,
		"192.000.002.001":     true,
		"subdomain.192.0.2.1": false,
		"0:0:0:0:0:0:0:1":     true,
		"::ffff:192.0.2.1":    true,
	}
	for host, want := range tests {
		if got := blocklist.blocks(host); got != want {
			t.Errorf("blocks(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestLoadBlocklistRejectsURLs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(path, []byte("https://example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadBlocklist(path); err == nil {
		t.Fatal("expected an invalid host error")
	}
}

func TestLoadBlocklistRejectsUnicodeHostnames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(path, []byte("münchen.de\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadBlocklist(path); err == nil {
		t.Fatal("expected an ASCII or Punycode error")
	}
}

func TestProxyForwardsHTTPAndLogsRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Proxy-Connection"); got != "" {
			t.Errorf("Proxy-Connection header reached backend: %q", got)
		}
		if got := r.Header.Get("X-Remove"); got != "" {
			t.Errorf("Connection-nominated header reached backend: %q", got)
		}
		w.Header().Set("X-Backend", "yes")
		_, _ = io.WriteString(w, "forwarded")
	}))
	t.Cleanup(backend.Close)

	proxyServer, logs := startTestProxy(t, nil)
	client := clientUsingProxy(t, proxyServer.URL)

	request, err := http.NewRequest(http.MethodGet, backend.URL+"/hello?token=secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Proxy-Connection", "keep-alive")
	request.Header.Set("Connection", "X-Remove")
	request.Header.Set("X-Remove", "yes")

	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if got := string(body); got != "forwarded" {
		t.Fatalf("body = %q, want %q", got, "forwarded")
	}
	if got := response.Header.Get("X-Backend"); got != "yes" {
		t.Fatalf("X-Backend = %q, want %q", got, "yes")
	}

	logOutput := logs.String()
	for _, want := range []string{"msg=request", "method=GET", "action=allowed"} {
		if !strings.Contains(logOutput, want) {
			t.Errorf("log output %q does not contain %q", logOutput, want)
		}
	}
	if strings.Contains(logOutput, "secret") {
		t.Errorf("log output contains query data: %q", logOutput)
	}
}

func TestProxyBlocksHTTP(t *testing.T) {
	proxyServer, logs := startTestProxy(t, hostBlocklist{"blocked.example": {}})
	client := clientUsingProxy(t, proxyServer.URL)

	response, err := client.Get("http://api.blocked.example/resource")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	if !strings.Contains(logs.String(), "action=blocked") {
		t.Fatalf("blocked request was not logged: %q", logs.String())
	}
}

func TestProxyTunnelsHTTPS(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secure")
	}))
	t.Cleanup(backend.Close)

	proxyServer, logs := startTestProxy(t, nil)
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := backend.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	t.Cleanup(transport.CloseIdleConnections)

	response, err := (&http.Client{Transport: transport}).Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if got := string(body); got != "secure" {
		t.Fatalf("body = %q, want %q", got, "secure")
	}
	for _, want := range []string{"msg=request", "method=CONNECT", "action=allowed"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log output %q does not contain %q", logs.String(), want)
		}
	}
}

func TestProxyClosesTunnelAfterClientDisconnects(t *testing.T) {
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = upstreamListener.Close()
	})

	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := upstreamListener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()

	handler := newProxy(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	handlerDone := make(chan struct{})
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		close(handlerDone)
	}))
	t.Cleanup(func() {
		handler.transport.CloseIdleConnections()
		proxyServer.Close()
	})

	client, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(
		client,
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		upstreamListener.Addr(),
		upstreamListener.Addr(),
	); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(
		bufio.NewReader(client),
		&http.Request{Method: http.MethodConnect},
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}

	upstream := <-accepted
	t.Cleanup(func() {
		_ = upstream.Close()
	})
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		_ = upstream.Close()
		t.Fatal("tunnel handler did not return after the client disconnected")
	}
}

func TestProxyBlocksCONNECT(t *testing.T) {
	proxyServer, logs := startTestProxy(t, hostBlocklist{"blocked.example": {}})

	connection, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
	})

	if _, err := fmt.Fprint(
		connection,
		"CONNECT api.blocked.example:443 HTTP/1.1\r\nHost: api.blocked.example:443\r\n\r\n",
	); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(
		bufio.NewReader(connection),
		&http.Request{Method: http.MethodConnect},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	if !strings.Contains(logs.String(), "method=CONNECT") ||
		!strings.Contains(logs.String(), "action=blocked") {
		t.Fatalf("blocked CONNECT was not logged: %q", logs.String())
	}
}

func TestProxyRejectsAbsoluteHTTPSRequest(t *testing.T) {
	logs := new(bytes.Buffer)
	handler := newProxy(nil, slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(handler.transport.CloseIdleConnections)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://example.com/resource", nil)
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if !strings.Contains(logs.String(), "action=rejected") {
		t.Fatalf("rejected request was not logged: %q", logs.String())
	}
}

func startTestProxy(
	t *testing.T,
	blocklist hostBlocklist,
) (*httptest.Server, *bytes.Buffer) {
	t.Helper()

	logs := new(bytes.Buffer)
	handler := newProxy(blocklist, slog.New(slog.NewTextHandler(logs, nil)))
	server := httptest.NewServer(handler)
	t.Cleanup(func() {
		handler.transport.CloseIdleConnections()
		server.Close()
	})
	return server, logs
}

func clientUsingProxy(t *testing.T, address string) *http.Client {
	t.Helper()

	proxyURL, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}
