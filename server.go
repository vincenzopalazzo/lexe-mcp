// SPDX-License-Identifier: Apache-2.0
// lexe-mcp — MCP server for Lexe Lightning.
// Direct Lexe gateway client (no lexe-sidecar): outer TLS pinned to Lexe's
// root CA, HTTPS CONNECT tunnel to run.lexe.app authenticated with the
// caller's long-lived gateway proxy token, inner mTLS with the revocable
// client certificate from the SDK credentials blob.
// Single file, stdlib only.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------- config ----------

type config struct {
	Port                  int
	Host                  string
	LexeClientCredentials string
	LexeNetwork           string // "mainnet" | "testnet3"
	PayMaxSats            int
	InvoiceDescription    string
	OfferTTL              int
}

var cfg config

const (
	protocolModern = "2026-07-28"
	protocol202511 = "2025-11-25"
	protocol202503 = "2025-03-26"
	serverName     = "lexe-mcp"
	serverVersion  = "2.0.0"
)

var supportedVersions = []string{protocolModern, protocol202511, protocol202503}

const serverInstructions = "Lexe Lightning MCP. Send Authorization: Bearer <Lexe SDK client credentials> (Lexe app → Menu → SDK clients) to use the invoice/payment tools. Modern clients (2026-07-28) should call server/discover first."

func parseConfigFile(path string) map[string]any {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[lexe-mcp] no config at %s (using env only)", path)
		} else {
			log.Fatalf("[lexe-mcp] cannot read config %s: %v", path, err)
		}
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		log.Fatalf("[lexe-mcp] cannot parse config %s: %v", path, err)
	}
	return m
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

func cfgInt(v any, def int) int {
	if v == nil {
		return def
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	s, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", v)))
	if err != nil {
		return def
	}
	return s
}

func envIntOrFileInt(env string, fileVal any, def int) int {
	if e := os.Getenv(env); e != "" {
		return cfgInt(e, def)
	}
	return cfgInt(fileVal, def)
}

// ---------- config load ----------


func envOr(env string, fileVal any) string {
	if e := os.Getenv(env); e != "" {
		return e
	}
	return asString(fileVal)
}

func looksPlaceholder(s string) bool {
	if s == "" {
		return true
	}
	u := strings.ToUpper(s)
	return strings.Contains(u, "PASTE") || strings.Contains(u, "YOUR_") || strings.Contains(u, "CHANGEME")
}

func loadConfig() config {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "config.json"
	}
	file := parseConfigFile(cfgPath)
	get := func(key string) any {
		if v, ok := file[key]; ok {
			return v
		}
		return nil
	}

	c := config{
		Port:                  envIntOrFileInt("PORT", get("port"), 8010),
		Host:                  envOr("HOST", get("host")),
		LexeClientCredentials: envOr("LEXE_CLIENT_CREDENTIALS", get("lexeClientCredentials")),
		LexeNetwork:           strings.ToLower(envOr("LEXE_NETWORK", get("lexeNetwork"))),
		PayMaxSats:            envIntOrFileInt("LEXE_PAY_MAX_SATS", get("payMaxSats"), 0),
		InvoiceDescription:    asString(get("invoiceDescription")),
		OfferTTL:              cfgInt(fmt.Sprintf("%v", get("offerTtlSecs")), 3600),
	}

	// defaults
	if c.Port == 0 {
		c.Port = 8010
	}
	if c.Host == "" {
		c.Host = "0.0.0.0"
	}
	if c.LexeNetwork == "" {
		c.LexeNetwork = "mainnet"
	}
	if c.LexeNetwork != "mainnet" && c.LexeNetwork != "testnet3" {
		log.Fatalf("[lexe-mcp] lexeNetwork must be mainnet or testnet3 (got %q)", c.LexeNetwork)
	}
	if c.InvoiceDescription == "" {
		c.InvoiceDescription = "Lightning payment"
	}
	if c.OfferTTL == 0 {
		c.OfferTTL = 3600
	}

	if looksPlaceholder(c.LexeClientCredentials) {
		c.LexeClientCredentials = ""
		log.Printf("[lexe-mcp] no server-side lexeClientCredentials — clients must send Authorization: Bearer <Lexe SDK credentials>")
	}
	return c
}

// ---------- lexe gateway client ----------
//
// Wire protocol (mirrors lexe-node-client from lexe-public, MIT):
//  1. outer TLS to the Lexe gateway, pinned to Lexe's own root CA;
//  2. HTTP CONNECT tunnel to run.lexe.app:443 with
//     `Proxy-Authorization: Bearer <lexe_auth_token>` (long-lived
//     GatewayProxy-scoped token embedded in the SDK credentials);
//  3. inner mTLS through the tunnel: we present the revocable client
//     certificate, the node presents a certificate signed by the ephemeral
//     issuing CA embedded in the credentials (or by the Lexe CA);
//  4. node commands are plain JSON REST (amounts are sats).

type httpError struct {
	msg string
}

func (e httpError) Error() string { return e.msg }

const (
	nodeRunHost = "run.lexe.app:443"
)

// gatewayAddr is a var so the hermetic tests can point it at a fake gateway.
var gatewayAddr = func() string {
	if cfg.LexeNetwork == "testnet3" {
		return "gateway.staging.lexe.app:443"
	}
	return "gateway.lexe.app:443"
}

// Lexe root CA certificates (DER, base64), from lexe-public
// lexe-common/data/lexe-{prod,staging}-root-ca-cert.der (valid to 2034).
const lexeProdCADERB64 = "MIIBszCCAWWgAwIBAgIUc7stsBNY1xzKpdNWp/MzW0w8YI4wBQYDK2VwMEQxCzAJBgNVBAYMAlVTMQswCQYDVQQIDAJDQTERMA8GA1UECgwIbGV4ZS1hcHAxFTATBgNVBAMMDExleGUgQ0EgY2VydDAeFw0yNDExMjcyMTQ0NDZaFw0zNDEyMDQyMTQ0NDZaMEQxCzAJBgNVBAYMAlVTMQswCQYDVQQIDAJDQTERMA8GA1UECgwIbGV4ZS1hcHAxFTATBgNVBAMMDExleGUgQ0EgY2VydDAqMAUGAytlcAMhAKYiHBR7wRReGKYKGOglEMUU5sVMTeed5icQX4pV/t0io2kwZzATBgNVHREEDDAKgghsZXhlLmFwcDAgBgNVHR4BAf8EFjAUoBIwCoIIbGV4ZS5hcHAwBIICbHgwHQYDVR0OBBYEFPO7LbATWNccyqXTVqfzM1tMPGCOMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EA9eUa9t1QTP0MMt/KzV/1damNLshlECOCrPJ1zFES6xAsTrZZ/s0USdPo6ldx2hHv9Fn39cQwk/Dfk0OodSigBg=="

const lexeStagingCADERB64 = "MIIBwzCCAXWgAwIBAgIUTlFBpeKEvuPOF8rLHlzMTEmVmNYwBQYDK2VwMEQxCzAJBgNVBAYMAlVTMQswCQYDVQQIDAJDQTERMA8GA1UECgwIbGV4ZS1hcHAxFTATBgNVBAMMDExleGUgQ0EgY2VydDAqMAUGAytlcAMhAP5S/9+Bk/XFjd6PHfjqrh7AtyJzZW7YF22OG3/hCK1Lo3kwdzATBgNVHREEDDAKgghsZXhlLmFwcDAwBgNVHR4BAf8EJjAkoCIwEoIQc3RhZ2luZy5sZXhlLmFwcDAMggpzdGFnaW5nLmx4MB0GA1UdDgQWBBTOUUGl4oS+484XysseXMxMSZWY1jAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANBAGVXs/0HwDSoRRPX9oHQgyxAKuAgBWRwLYYlgxG4qPDl6dzqnOiQkIvgYOe1Q51XyXN8suHdIDh2xqjaufUlug0="

var (
	gatewayCAPool = sync.OnceValue(func() *x509.CertPool {
		b64 := lexeProdCADERB64
		if cfg.LexeNetwork == "testnet3" {
			b64 = lexeStagingCADERB64
		}
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			log.Fatalf("[lexe-mcp] embedded Lexe CA: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			log.Fatalf("[lexe-mcp] embedded Lexe CA: %v", err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		return pool
	})
)

// lexeCreds is the parsed SDK client-credentials blob.
type lexeCreds struct {
	proxyToken string            // long-lived GatewayProxy bearer token
	clientCert tls.Certificate   // revocable client cert + key (inner mTLS)
	ephCA      *x509.Certificate // ephemeral issuing CA (inner trust anchor)
}

// parseLexeCreds decodes the base64 JSON blob exported by the Lexe app
// (Menu → SDK clients): {user_pk?, client_pk, rev_client_key_der,
// rev_client_cert_der, eph_ca_cert_der, lexe_auth_token} — DER/hex fields.
func parseLexeCreds(blob string) (*lexeCreds, error) {
	s := strings.TrimSpace(blob)
	s = strings.TrimRight(s, "=")
	raw, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, httpError{"Lexe identity is not a valid SDK credentials blob (bad base64)"}
	}
	var m struct {
		UserPK          string `json:"user_pk"`
		ClientPK        string `json:"client_pk"`
		RevClientKey    string `json:"rev_client_key_der"`
		RevClientCert   string `json:"rev_client_cert_der"`
		EphCACert       string `json:"eph_ca_cert_der"`
		LexeAuthToken   string `json:"lexe_auth_token"`
		GatewayProxyTok string `json:"gateway_proxy_token"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, httpError{"Lexe identity is not a valid SDK credentials blob (bad JSON)"}
	}
	token := m.LexeAuthToken
	if token == "" {
		token = m.GatewayProxyTok
	}
	if token == "" {
		return nil, httpError{"Lexe identity has no lexe_auth_token (re-export SDK client credentials from the Lexe app)"}
	}
	keyDER, err := hex.DecodeString(strings.TrimPrefix(m.RevClientKey, "0x"))
	if err != nil || len(keyDER) == 0 {
		return nil, httpError{"Lexe identity has no rev_client_key_der"}
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, httpError{"Lexe identity: cannot parse revocable client key: " + err.Error()}
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, httpError{"Lexe identity: revocable client key is not ed25519"}
	}
	certDER, err := hex.DecodeString(strings.TrimPrefix(m.RevClientCert, "0x"))
	if err != nil || len(certDER) == 0 {
		return nil, httpError{"Lexe identity has no rev_client_cert_der"}
	}
	caDER, err := hex.DecodeString(strings.TrimPrefix(m.EphCACert, "0x"))
	if err != nil || len(caDER) == 0 {
		return nil, httpError{"Lexe identity has no eph_ca_cert_der"}
	}
	ephCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, httpError{"Lexe identity: cannot parse ephemeral CA cert: " + err.Error()}
	}
	return &lexeCreds{
		proxyToken: token,
		clientCert: tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: edKey},
		ephCA:      ephCA,
	}, nil
}

// resolveCreds picks the caller's per-request identity, falling back to the
// server config. The caller's identity is used for its own node, always.
func resolveCreds(creds string) (*lexeCreds, error) {
	if creds == "" {
		creds = cfg.LexeClientCredentials
	}
	if creds == "" {
		return nil, httpError{"missing Lexe identity: send Authorization: Bearer <SDK client credentials>"}
	}
	return parseLexeCreds(creds)
}

// bufConn lets tls.Client read through an already-buffered reader (the
// CONNECT response may have buffered bytes past its end).
type bufConn struct {
	r *bufio.Reader
	c net.Conn
}

func (b bufConn) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b bufConn) Write(p []byte) (int, error) { return b.c.Write(p) }
func (b bufConn) Close() error                { return b.c.Close() }
func (b bufConn) LocalAddr() net.Addr         { return b.c.LocalAddr() }
func (b bufConn) RemoteAddr() net.Addr        { return b.c.RemoteAddr() }
func (b bufConn) SetDeadline(t time.Time) error      { return b.c.SetDeadline(t) }
func (b bufConn) SetReadDeadline(t time.Time) error  { return b.c.SetReadDeadline(t) }
func (b bufConn) SetWriteDeadline(t time.Time) error { return b.c.SetWriteDeadline(t) }

// nodeTunnel opens outer-TLS → CONNECT → inner-mTLS to the user's node.
func nodeTunnel(lc *lexeCreds, timeout time.Duration) (net.Conn, error) {
	gw := gatewayAddr()
	gwHost, _, err := net.SplitHostPort(gw)
	if err != nil {
		return nil, err
	}
	outer, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", gw, &tls.Config{
		// Trust ONLY Lexe's root CA — no WebPKI roots, like rustls
		// user_gateway_client_config.
		RootCAs:    gatewayCAPool(),
		ServerName: gwHost,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return nil, httpError{fmt.Sprintf("gateway TLS (%s): %v", gw, redactTLS(err))}
	}
	if err := outer.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err // outer closed by the defer below
	}
	defer func() {
		if err != nil {
			outer.Close()
		}
	}()

	// CONNECT through the gateway proxy with the long-lived proxy token.
	// (Hand-rolled: http.Request.Write prefixes the URI with '/', which the
	// gateway's proxy would reject.)
	br := bufio.NewReader(outer)
	connect := "CONNECT " + nodeRunHost + " HTTP/1.1\r\n" +
		"Host: " + nodeRunHost + "\r\n" +
		"Proxy-Authorization: Bearer " + lc.proxyToken + "\r\n\r\n"
	if _, err := outer.Write([]byte(connect)); err != nil {
		return nil, httpError{"gateway CONNECT write: " + redactTLS(err)}
	}
	connectReq := &http.Request{Method: http.MethodConnect}
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		return nil, httpError{"gateway CONNECT read: " + redactTLS(err)}
	}
	resp.Body.Close() // never drained: a 200 CONNECT body reads-until-EOF
	if resp.StatusCode != http.StatusOK {
		outer.Close()
		return nil, httpError{fmt.Sprintf("gateway CONNECT rejected: HTTP %d (proxy token rejected?)", resp.StatusCode)}
	}

	// Inner mTLS to the node inside the tunnel. The node's certificate must
	// chain to the credentials' ephemeral CA or the Lexe CA (CA pinning is
	// the boundary; run.lexe.app is a routing name, not a DNS identity).
	ephPool := x509.NewCertPool()
	ephPool.AddCert(lc.ephCA)
	inner := tls.Client(bufConn{r: br, c: outer}, &tls.Config{
		InsecureSkipVerify: true, // verified below against pinned CAs
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyNodeChain(rawCerts, ephPool)
		},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &lc.clientCert, nil
		},
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	hctx, hcancel := context.WithTimeout(context.Background(), timeout)
	defer hcancel()
	if err := inner.HandshakeContext(hctx); err != nil {
		outer.Close()
		return nil, httpError{"node TLS (tunnel): " + redactTLS(err)}
	}
	return inner, nil
}

// verifyNodeChain checks the leaf chains to the ephemeral CA (or, for
// older credentials, the Lexe root CA) and carries ServerAuth usage.
func verifyNodeChain(rawCerts [][]byte, ephPool *x509.CertPool) error {
	if len(rawCerts) == 0 {
		return httpError{"node presented no certificate"}
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	inters := x509.NewCertPool()
	for _, c := range rawCerts[1:] {
		if cert, err := x509.ParseCertificate(c); err == nil {
			inters.AddCert(cert)
		}
	}
	for _, pool := range []*x509.CertPool{ephPool, gatewayCAPool()} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inters}); err == nil {
			if len(leaf.ExtKeyUsage) > 0 {
				ok := false
				for _, ku := range leaf.ExtKeyUsage {
					if ku == x509.ExtKeyUsageServerAuth {
						ok = true
						break
					}
				}
				if !ok {
					continue
				}
			}
			return nil
		}
	}
	return httpError{"node certificate does not chain to the credentials' ephemeral CA or the Lexe CA"}
}

// redactTLS keeps TLS errors (which can embed certificate bytes) terse.
func redactTLS(err error) string {
	s := err.Error()
	if i := strings.Index(s, "\n"); i > 0 {
		s = s[:i]
	}
	return s
}

// nodeCall performs one JSON REST call against the user's node through a
// fresh tunnel. Amounts are sats (Lexe Decimal Amount convention).
func nodeCall(method, path string, body any, timeoutMs int, creds string) (any, error) {
	lc, err := resolveCreds(creds)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	conn, err := nodeTunnel(lc, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var payload []byte
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, "https://"+nodeRunHost+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Host = nodeRunHost
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", serverName+"/"+serverVersion)
	req.Header.Set("Connection", "close")
	if err := req.Write(conn); err != nil {
		return nil, httpError{"node request write: " + redactTLS(err)}
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, httpError{"node request: " + redactTLS(err)}
	}
	defer resp.Body.Close()
	text, readErr := io.ReadAll(resp.Body)
	if readErr != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil, httpError{"node response read: " + redactTLS(readErr)}
	}
	var out any
	if len(text) > 0 {
		if err := json.Unmarshal(text, &out); err != nil {
			out = map[string]any{"raw": string(text)}
		}
	} else {
		out = map[string]any{}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s := string(text)
		if len(s) > 300 {
			s = s[:300]
		}
		return out, httpError{fmt.Sprintf("node %s %s -> %d: %s", method, path, resp.StatusCode, s)}
	}
	return out, nil
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func createOffer(description string, minAmountSats int, ttlSecs any, creds string) (map[string]any, error) {
	if description == "" {
		description = cfg.InvoiceDescription
	}
	if len(description) > 200 {
		description = description[:200]
	}
	ttl := cfg.OfferTTL
	if ttlSecs != nil {
		ttl = cfgInt(ttlSecs, cfg.OfferTTL)
	}
	body := map[string]any{
		"description":     description,
		"expiration_secs": ttl,
	}
	if minAmountSats > 0 {
		body["min_amount"] = strconv.Itoa(minAmountSats) // sats
	}
	out, err := nodeCall("POST", "/user/v1/create_offer", body, 120000, creds)
	if err != nil {
		return nil, err
	}
	return asMap(out), nil
}

var errPaymentNotFound = httpError{"payment not found"}

func getPayment(index string, creds string) (map[string]any, error) {
	id, err := paymentIDFromIndex(index)
	if err != nil {
		return nil, err
	}
	out, err := nodeCall("GET", "/user/v1/payments/id?id="+url.QueryEscape(id), nil, 120000, creds)
	if err != nil {
		return nil, err
	}
	m := asMap(out)
	if m == nil {
		return nil, httpError{"node payments/id: unexpected response"}
	}
	if p := asMap(m["maybe_payment"]); p != nil {
		return p, nil
	}
	return nil, errPaymentNotFound
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func clipNote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

func satsInt(v any) (int, bool) {
	if v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		if n <= 0 {
			return 0, false
		}
		return int(n), true
	case int:
		if n <= 0 {
			return 0, false
		}
		return n, true
	case int64:
		if n <= 0 {
			return 0, false
		}
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil || i <= 0 {
			return 0, false
		}
		return int(i), true
	case string:
		s := strings.TrimSpace(n)
		if s == "" {
			return 0, false
		}
		i, err := strconv.Atoi(s)
		if err != nil || i <= 0 {
			return 0, false
		}
		return i, true
	}
	return 0, false
}

func payableFromArgs(args map[string]any) string {
	for _, k := range []string{"invoice", "offer", "payable", "payment_string"} {
		if s := strings.TrimSpace(asString(args[k])); s != "" {
			return s
		}
	}
	return ""
}

func isLightningKind(kind string) bool {
	switch strings.ToLower(kind) {
	case "invoice", "offer", "lnurl-pay", "lnurl":
		return true
	}
	return false
}

func payableEncoding(p map[string]any) string {
	return firstString(p, "invoice", "offer", "lnurl")
}

// pickLightningPayable picks the Lightning route from the local analysis
// and skips on-chain. Empty map + error if there is nothing we will send.
func pickLightningPayable(analyzed map[string]any) (map[string]any, error) {
	for _, item := range asSlice(analyzed["payables"]) {
		p := asMap(item)
		if p == nil {
			continue
		}
		if isLightningKind(asString(p["kind"])) {
			return p, nil
		}
	}
	if len(asSlice(analyzed["claimables"])) > 0 {
		return nil, httpError{"that string is a withdraw/claim, not a payable invoice or offer"}
	}
	return nil, httpError{"no Lightning invoice or offer in that string (on-chain sends are not supported)"}
}

func resolvePayAmount(picked map[string]any, requested, maxSats int) (int, error) {
	encoded, hasEncoded := satsInt(picked["amount"])
	minA, _ := satsInt(picked["min_amount"])
	maxA, _ := satsInt(picked["max_amount"])
	if requested > 0 && hasEncoded && requested != encoded {
		return 0, httpError{fmt.Sprintf("amount_sats %d does not match invoice amount %d", requested, encoded)}
	}
	amt := requested
	if amt == 0 && hasEncoded {
		amt = encoded
	}
	if amt == 0 {
		return 0, httpError{"amountless invoice/offer: pass amount_sats"}
	}
	if maxSats > 0 && amt > maxSats {
		return 0, httpError{fmt.Sprintf("amount %d sats exceeds payMaxSats %d", amt, maxSats)}
	}
	if minA > 0 && amt < minA {
		return 0, httpError{fmt.Sprintf("amount %d sats is below the recipient min %d", amt, minA)}
	}
	if maxA > 0 && amt > maxA {
		return 0, httpError{fmt.Sprintf("amount %d sats is above the recipient max %d", amt, maxA)}
	}
	return amt, nil
}

// analyzePaymentString decodes a payment string LOCALLY (the SDK's
// analyze is client-side too). Kinds: invoice | offer | lnurl-pay | onchain.
func analyzePaymentString(paymentString, _ string) (map[string]any, error) {
	payable, kind := classifyPayable(paymentString)
	if payable == "" {
		return nil, httpError{"cannot classify that string as an invoice, offer, LNURL, or address"}
	}
	p := map[string]any{"kind": kind}
	switch kind {
	case "invoice":
		p["invoice"] = payable
		if sats, ok := bolt11AmountSats(payable); ok {
			p["amount"] = sats
		}
	case "offer":
		p["offer"] = payable
	case "lnurl-pay", "lnurl":
		p["lnurl"] = payable
	case "onchain":
		return map[string]any{"payables": []any{}, "claimables": []any{}}, nil
	}
	return map[string]any{"payables": []any{p}, "claimables": []any{}}, nil
}

// classifyPayable returns the canonical string and its kind.
func classifyPayable(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, "lno1"):
		return s, "offer"
	case isBolt11(low):
		return s, "invoice"
	case strings.HasPrefix(low, "lnurl"), isLightningAddress(s):
		return s, "lnurl-pay"
	case strings.HasPrefix(low, "bc1"), isProbablyOnchain(low):
		return s, "onchain"
	}
	return "", ""
}

// isBolt11: hr part "ln<net>" + optional amount + separator '1'. The
// separator is the LAST '1' — bech32 data never contains it.
func isBolt11(s string) bool {
	if !strings.HasPrefix(s, "ln") || len(s) < 6 {
		return false
	}
	sep := strings.LastIndexByte(s, '1')
	if sep < 4 { // no separator after the network part
		return false
	}
	amount := s[4:sep]
	if amount == "" {
		return true
	}
	digits := amount[:len(amount)-1]
	mult := amount[len(amount)-1]
	if mult >= '0' && mult <= '9' {
		digits = amount
		mult = 0
	}
	if digits == "" {
		return false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	switch mult {
	case 0, 'm', 'u', 'n', 'p':
		return true
	}
	return false
}

// bolt11AmountSats parses the hrpart amount ("lnbc10u1…" → 1000). BOLT11
// multipliers are BTC fractions: m=milli, u=micro, n=nano, p=pico. The
// separator is the LAST '1' (bech32 data never contains it).
func bolt11AmountSats(invoice string) (int, bool) {
	low := strings.ToLower(strings.TrimSpace(invoice))
	sep := strings.LastIndexByte(low, '1')
	if sep < 4 {
		return 0, false
	}
	amount := low[4:sep]
	if amount == "" {
		return 0, false // amountless invoice
	}
	mult := byte(0)
	if c := amount[len(amount)-1]; c < '0' || c > '9' {
		mult = c
		amount = amount[:len(amount)-1]
	}
	n, err := strconv.ParseUint(amount, 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	// 21M BTC in sats is the chain limit; anything beyond is invalid input.
	const maxSats = uint64(21000000) * 100000000
	if n > maxSats {
		return 0, false
	}
	safe := func(sats uint64) (int, bool) {
		if sats > maxSats || sats > uint64(^uint(0)>>1) {
			return 0, false
		}
		return int(sats), sats > 0
	}
	switch mult {
	case 0:
		if n > maxSats/100000000 {
			return 0, false
		}
		return safe(n * 100000000)
	case 'm':
		if n > maxSats/100000 {
			return 0, false
		}
		return safe(n * 100000)
	case 'u':
		if n > maxSats/100 {
			return 0, false
		}
		return safe(n * 100)
	case 'n':
		return safe(n / 10)
	case 'p':
		return 0, false // sub-sat precision — treat as amountless
	}
	return 0, false
}

func isLightningAddress(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	domain := s[at+1:]
	dot := strings.IndexByte(domain, '.')
	return dot > 0 && dot < len(domain)-1 && !strings.ContainsAny(s, " \t/")
}

func isProbablyOnchain(s string) bool {
	if len(s) < 14 || len(s) > 90 {
		return false
	}
	switch {
	case strings.HasPrefix(s, "bc1"), strings.HasPrefix(s, "tb1"),
		strings.HasPrefix(s, "bcrt1"):
		return true
	case s[0] == '1' || s[0] == '3' || s[0] == '0':
		for _, c := range s {
			if !((c >= '1' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '0') {
				return false
			}
		}
		return true
	}
	return false
}

// paymentIDFromIndex splits "<19-digit created_at>-<id>" into the payment id.
func paymentIDFromIndex(index string) (string, error) {
	index = strings.TrimSpace(index)
	i := strings.IndexByte(index, '-')
	if i <= 0 || i == len(index)-1 {
		return "", httpError{"invalid payment index (expected <created_at>-<payment_id>)"}
	}
	return index[i+1:], nil
}

// sendLightningPay pays over the direct node connection and waits for a
// terminal state (mirrors the wallet's wait_for_payment backoff).
func sendLightningPay(picked map[string]any, amt int, note, creds string) (map[string]any, error) {
	kind := strings.ToLower(asString(picked["kind"]))
	raw := payableEncoding(picked)
	if raw == "" {
		return nil, httpError{"analyze returned a Lightning payable with no invoice/offer string"}
	}
	body := map[string]any{}
	if note != "" {
		body["personal_note"] = note
	}
	var paymentID string
	var createdAt int64

	switch kind {
	case "invoice":
		body["invoice"] = raw
		if _, hasAmt := satsInt(picked["amount"]); !hasAmt {
			body["fallback_amount"] = strconv.Itoa(amt) // sats
		}
		out, err := nodeCall("POST", "/user/v1/pay_invoice", body, 60000, creds)
		if err != nil {
			return nil, err
		}
		createdAt = int64(toInt64(asMap(out)["created_at"]))
		payment, err := waitPaymentByCreated(createdAt, amt, creds)
		if err != nil {
			return nil, httpError{fmt.Sprintf("invoice payment submitted at %d but %s", createdAt, err.Error())}
		}
		return payment, nil
	case "offer":
		var cid [32]byte
		if _, err := rand.Read(cid[:]); err != nil {
			return nil, err
		}
		cidHex := hex.EncodeToString(cid[:])
		body["cid"] = cidHex
		body["offer"] = raw
		body["amount"] = strconv.Itoa(amt) // sats
		out, err := nodeCall("POST", "/user/v1/pay_offer", body, 60000, creds)
		if err != nil {
			return nil, err
		}
		createdAt = int64(toInt64(asMap(out)["created_at"]))
		paymentID = "fs_" + cidHex
	case "lnurl-pay", "lnurl":
		return nil, httpError{"LNURL and Lightning-address payments are not supported by the direct gateway — resolve to a BOLT11 invoice (lnbc…) and pass that"}
	default:
		return nil, httpError{"unsupported payable kind: " + kind}
	}

	payment, err := waitPaymentByID(paymentID, creds)
	if err != nil {
		// The payment was submitted; surface the index so the caller can
		// poll lexe.check_payment instead of blind-retrying lexe.pay.
		return map[string]any{
			"index":  paymentIndex(createdAt, paymentID),
			"status": "unknown",
			"error":  err.Error(),
		}, nil
	}
	if payment == nil {
		return map[string]any{
			"index":  paymentIndex(createdAt, paymentID),
			"status": "pending",
		}, nil
	}
	return payment, nil
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case string:
		i, _ := strconv.ParseInt(strings.TrimSpace(n), 10, 64)
		return i
	}
	return 0
}

// paymentIndex formats "<zero-padded 19 created_at>-<id>".
func paymentIndex(createdAt int64, id string) string {
	return fmt.Sprintf("%019d-%s", createdAt, id)
}

// waitPaymentByID polls until completed|failed or the deadline (~150 s).
func waitPaymentByID(id, creds string) (map[string]any, error) {
	return waitPayment(func() (map[string]any, error) {
		p, err := getPayment("0-"+id, creds)
		if err != nil {
			if err == errPaymentNotFound {
				return nil, nil // registered, not visible yet — keep polling
			}
			return nil, err
		}
		return p, nil
	})
}

// waitPaymentByCreated finds an invoice payment by its registration time via
// payments/updated (the invoice payment id is derived inside the node).
// Matching: created_at + outbound + invoice kind + amount — a same-ms
// collision from another payment must also match all of those.
func waitPaymentByCreated(createdAt int64, amt int, creds string) (map[string]any, error) {
	minID := "ln_" + strings.Repeat("0", 64)
	start := fmt.Sprintf("u%019d-%s", createdAt-1, minID)
	return waitPayment(func() (map[string]any, error) {
		out, err := nodeCall("GET", "/user/v1/payments/updated?start_index="+url.QueryEscape(start)+"&limit=50", nil, 30000, creds)
		if err != nil {
			return nil, err
		}
		m := asMap(out)
		for _, item := range asSlice(m["payments"]) {
			p := asMap(item)
			if p == nil {
				continue
			}
			if toInt64(p["created_at"]) != createdAt {
				continue
			}
			if !strings.Contains(strings.ToLower(asString(p["direction"])), "outbound") {
				continue
			}
			if k := strings.ToLower(asString(p["kind"])); k != "" && k != "invoice" {
				continue
			}
			if s, ok := satsInt(p["amount"]); ok && s != amt {
				continue
			}
			return p, nil
		}
		return nil, nil // registered, not visible yet — keep polling
	})
}

// waitPayment polls until completed|failed or the ~150 s deadline. Poll
// ERRORS are tolerated (recorded, retried): once a payment is submitted the
// money may move regardless, so a transient network error must not surface
// as a bare failure an agent would "retry" with a second payment.
func waitPayment(poll func() (map[string]any, error)) (map[string]any, error) {
	deadline := time.Now().Add(150 * time.Second)
	wait := 250 * time.Millisecond
	const maxWait = 4 * time.Second
	var lastErr error
	for {
		p, err := poll()
		if err != nil {
			lastErr = err
		} else if p != nil {
			s := strings.ToLower(asString(p["status"]))
			if s == "completed" || s == "failed" {
				return p, nil
			}
		}
		if time.Now().After(deadline) {
			if p != nil {
				return p, nil // pending past the deadline
			}
			if lastErr != nil {
				return nil, httpError{"payment status unknown (submitted; poll error: " + lastErr.Error() + ") — do NOT blind-retry lexe.pay; check lexe.check_payment when you have the index"}
			}
			return nil, httpError{"payment did not settle within 150 s (it may still settle — check with lexe.check_payment)"}
		}
		time.Sleep(wait)
		if wait < maxWait {
			wait *= 2
		}
	}
}

const lnproofSpaceBase = "https://lnproof.space"

func payerProofLink(proof string) string {
	proof = strings.TrimSpace(proof)
	if !strings.HasPrefix(strings.ToLower(proof), "lnp1") {
		return ""
	}
	return lnproofSpaceBase + "/" + proof
}

func createPayerProof(index, proofNote, creds string) (string, error) {
	index = strings.TrimSpace(index)
	if index == "" {
		return "", httpError{"missing payment index for payer proof"}
	}
	body := map[string]any{
		"index": index,
		// Default disclosures, matching PayerProofDisclosures::default().
		"disclosures": map[string]any{
			"offer_description":   true,
			"invreq_payer_note":   true,
			"invoice_amount":      true,
			"invoice_created_at":  true,
		},
	}
	if proofNote != "" {
		body["proof_note"] = proofNote
	}
	out, err := nodeCall("POST", "/user/v1/create_payer_proof", body, 30000, creds)
	if err != nil {
		return "", err
	}
	proof := firstString(asMap(out), "proof")
	if proof == "" {
		return "", httpError{"node create_payer_proof returned no proof"}
	}
	return proof, nil
}

func paymentSettled(p map[string]any) bool {
	if p == nil {
		return false
	}
	s := strings.ToLower(asString(p["status"]))
	return s == "completed" || s == "settled" || s == "paid"
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// ---------- request identity ----------

// bearerToken returns the raw Authorization Bearer value, if any.
func bearerToken(r *http.Request) string {
	a := strings.TrimSpace(r.Header.Get("Authorization"))
	if a == "" {
		return ""
	}
	if len(a) >= 7 && strings.EqualFold(a[:7], "Bearer ") {
		return strings.TrimSpace(a[7:])
	}
	return ""
}

// bearerLexe is a Lexe SDK client-credentials blob (base64 JSON). Used as
// the per-request identity for the direct gateway connection.
func bearerLexe(r *http.Request) string {
	return bearerToken(r)
}

func writeJSON(w http.ResponseWriter, code int, obj any, extra ...map[string]string) {
	body, _ := json.Marshal(obj)
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Headers", "*")
	h.Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
	for _, m := range extra {
		for k, v := range m {
			h.Set(k, v)
		}
	}
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// ---------- MCP tools ----------

var TOOLS []map[string]any

func buildTools() []map[string]any {
	return []map[string]any{
		{
			"name":        "lexe.create_invoice",
			"title":       "Create Lightning invoice",
			"description": "Create a fresh BOLT12 offer (reusable, min amount in sats) on the caller's Lexe node. Pay it with any Lightning wallet that supports offers.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"description": map[string]any{"type": "string", "description": "Invoice description (<=200 chars)"},
					"amount_sats": map[string]any{"type": "number", "description": "Min amount in sats (default 1)"},
				},
			},
		},
		{
			"name":        "lexe.check_payment",
			"title":       "Check Lightning payment",
			"description": "Check whether a payment (by index) has settled.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"index": map[string]any{"type": "string", "description": "Payment index returned by lexe.pay"},
				},
				"required": []string{"index"},
			},
		},
		{
			"name":        "lexe.node_health",
			"title":       "Lexe node health",
			"description": "The caller's Lexe node info (version, balances, channels) fetched over the Lexe gateway. Requires the caller's identity.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "lexe.analyze",
			"title":       "Analyze invoice or offer",
			"description": "Decode a BOLT11 invoice (lnbc…) or BOLT12 offer (lno1…) locally without sending. Returns amount/kind so you can inspect before lexe.pay. LNURL strings and Lightning addresses are recognized but not payable.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"invoice":        map[string]any{"type": "string", "description": "BOLT11 invoice or BOLT12 offer"},
					"offer":          map[string]any{"type": "string", "description": "Alias for invoice when the string is a BOLT12 offer"},
					"payment_string": map[string]any{"type": "string", "description": "Alias for invoice"},
				},
			},
		},
		{
			"name":        "lexe.pay",
			"title":       "Pay invoice or offer",
			"description": "Pay a Lightning invoice or offer from the caller's Lexe node. Pass the BOLT11 (lnbc…) or BOLT12 offer (lno1…) string. Amountless strings need amount_sats. On-chain addresses and LNURL are refused. After a settled BOLT12 offer pay, also returns a payer proof (lnp1…) and proof_url on lnproof.space.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"invoice":     map[string]any{"type": "string", "description": "BOLT11 invoice (lnbc…) or BOLT12 offer (lno1…)"},
					"offer":       map[string]any{"type": "string", "description": "Alias for invoice when paying a BOLT12 offer"},
					"amount_sats": map[string]any{"type": "number", "description": "Sats to send. Required if the invoice/offer has no amount. Must match a fixed invoice amount."},
					"note":        map[string]any{"type": "string", "description": "Personal note stored on the node, not sent to the receiver (<=200 chars)"},
					"proof_note":  map[string]any{"type": "string", "description": "Optional public note bound into a BOLT12 payer proof (offer pays only, <=200 chars)"},
				},
			},
		},
	}
}

// callLexeTool dispatches one MCP tool call to the caller's Lexe node.
// creds is the per-request Lexe SDK identity (empty → server config fallback).
func callLexeTool(name string, args map[string]any, creds string) (any, error) {
	switch name {
	case "lexe.create_invoice":
		if _, err := resolveCreds(creds); err != nil {
			return nil, err
		}
		desc := asString(args["description"])
		amt := cfgInt(args["amount_sats"], 1)
		offer, err := createOffer(desc, amt, args["ttl_secs"], creds)
		if err != nil {
			return nil, err
		}
		bolt12 := firstString(offer, "offer", "bolt12")
		if bolt12 == "" {
			if inner := asMap(offer["offer"]); inner != nil {
				bolt12 = firstString(inner, "bolt12")
			}
		}
		return map[string]any{"ok": true, "offer": bolt12, "raw": offer}, nil
	case "lexe.check_payment":
		if _, err := resolveCreds(creds); err != nil {
			return nil, err
		}
		index := strings.TrimSpace(asString(args["index"]))
		if index == "" {
			return nil, httpError{"missing index"}
		}
		p, err := getPayment(index, creds)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "settled": paymentSettled(p), "payment": p}, nil
	case "lexe.node_health":
		out, err := nodeCall("GET", "/user/v2/node_info", nil, 30000, creds)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "node_info": out}, nil
	case "lexe.analyze":
		s := payableFromArgs(args)
		if s == "" {
			return nil, httpError{"missing invoice/offer string"}
		}
		analyzed, err := analyzePaymentString(s, creds)
		if err != nil {
			return nil, err
		}
		picked, pickErr := pickLightningPayable(analyzed)
		out := map[string]any{"ok": pickErr == nil, "analyzed": analyzed}
		if pickErr != nil {
			out["error"] = pickErr.Error()
		} else {
			out["payable"] = picked
		}
		return out, nil
	case "lexe.pay":
		if _, err := resolveCreds(creds); err != nil {
			return nil, err
		}
		s := payableFromArgs(args)
		if s == "" {
			return nil, httpError{"missing invoice/offer: pass invoice or offer"}
		}
		analyzed, err := analyzePaymentString(s, creds)
		if err != nil {
			return nil, err
		}
		picked, err := pickLightningPayable(analyzed)
		if err != nil {
			return nil, err
		}
		amt, err := resolvePayAmount(picked, cfgInt(args["amount_sats"], 0), cfg.PayMaxSats)
		if err != nil {
			return nil, err
		}
		note := clipNote(asString(args["note"]))
		p, err := sendLightningPay(picked, amt, note, creds)
		if err != nil {
			return nil, err
		}
		if p == nil {
			p = map[string]any{}
		}
		kind := asString(picked["kind"])
		idx := paymentIndex(toInt64(p["created_at"]), asString(p["id"]))
		if asString(p["id"]) == "" {
			idx = asString(p["index"])
		}
		out := map[string]any{
			"ok":      paymentSettled(p),
			"settled": paymentSettled(p),
			"index":   idx,
			"status":  asString(p["status"]),
			"amount":  amt,
			"kind":    kind,
			"payment": p,
		}
		if strings.EqualFold(kind, "offer") && paymentSettled(p) {
			proof, perr := createPayerProof(idx, clipNote(asString(args["proof_note"])), creds)
			if perr != nil {
				log.Printf("[lexe-mcp] create_payer_proof %s: %v", idx, perr)
				out["proof_error"] = perr.Error()
			} else {
				out["proof"] = proof
				out["proof_url"] = payerProofLink(proof)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown tool %s", name)
	}
}

// ---------- MCP protocol (dual-era: 2026-07-28 + initialize handshake) ----------
//
// Current MCP revision is 2026-07-28 (https://modelcontextprotocol.io/docs/2026-07-28/getting-started/intro).
// That revision is stateless: no initialize handshake, every request carries
// `_meta.io.modelcontextprotocol/protocolVersion`, servers MUST implement
// `server/discover`, tools/call results MUST include resultType+content, and
// Streamable HTTP requires MCP-Protocol-Version / Mcp-Method headers.
//
// We remain dual-era so existing Goose / Claude / Inspector clients that still
// speak 2025-03-26 (`initialize` + ping, no headers) keep working. Missing
// MCP-Protocol-Version is treated as 2025-03-26.

func serverInfo() map[string]any {
	return map[string]any{"name": serverName, "version": serverVersion}
}

func serverMeta() map[string]any {
	return map[string]any{"io.modelcontextprotocol/serverInfo": serverInfo()}
}

func jsonRPCResult(id any, result any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
}

func jsonRPCErr(id any, code int, message string, data any) map[string]any {
	err := map[string]any{"code": code, "message": message}
	if data != nil {
		err["data"] = data
	}
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": err}
}

func toolCallResult(data any, isErr bool) map[string]any {
	text, _ := json.Marshal(data)
	res := map[string]any{
		"resultType": "complete",
		"content":    []map[string]any{{"type": "text", "text": string(text)}},
		"isError":    isErr,
		"_meta":      serverMeta(),
	}
	if !isErr {
		res["structuredContent"] = data
	}
	return res
}

func toolsListResult() map[string]any {
	return map[string]any{
		"resultType": "complete",
		"tools":      TOOLS,
		"ttlMs":      300000,
		"cacheScope": "public",
		"_meta":      serverMeta(),
	}
}

func discoverResult() map[string]any {
	return map[string]any{
		"resultType":        "complete",
		"supportedVersions": supportedVersions,
		"capabilities":      map[string]any{"tools": map[string]any{}},
		"_meta":             serverMeta(),
		"instructions":      serverInstructions,
		"ttlMs":             3600000,
		"cacheScope":        "public",
	}
}

func initializeResult(requested string) map[string]any {
	ver := protocol202503
	if requested == protocol202511 || requested == protocol202503 {
		ver = requested
	}
	return map[string]any{
		"protocolVersion": ver,
		"serverInfo":      serverInfo(),
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"instructions":    serverInstructions,
	}
}

func decodeMCPHeader(v string) string {
	v = strings.TrimSpace(v)
	const pfx, sfx = "=?base64?", "?="
	if strings.HasPrefix(v, pfx) && strings.HasSuffix(v, sfx) {
		raw := strings.TrimSuffix(strings.TrimPrefix(v, pfx), sfx)
		if b, err := base64.StdEncoding.DecodeString(raw); err == nil {
			return string(b)
		}
	}
	return v
}

func protocolHeader(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version")); v != "" {
		return v
	}
	return strings.TrimSpace(r.Header.Get("Mcp-Protocol-Version"))
}

func requestMeta(m map[string]any) map[string]any {
	params, _ := m["params"].(map[string]any)
	if params == nil {
		return nil
	}
	meta, _ := params["_meta"].(map[string]any)
	return meta
}

func requestedVersion(r *http.Request, m map[string]any) (ver string, mismatch string) {
	header := protocolHeader(r)
	var body string
	if meta := requestMeta(m); meta != nil {
		body = asString(meta["io.modelcontextprotocol/protocolVersion"])
	}
	if header != "" && body != "" && header != body {
		return "", "MCP-Protocol-Version header value '" + header + "' does not match body value '" + body + "'"
	}
	if header != "" {
		return header, ""
	}
	if body != "" {
		return body, ""
	}
	if asString(m["method"]) == "initialize" {
		if params, _ := m["params"].(map[string]any); params != nil {
			if v := asString(params["protocolVersion"]); v != "" {
				return v, ""
			}
		}
	}
	// Dual-era: omitted header ⇒ legacy Streamable HTTP (2025-03-26).
	return protocol202503, ""
}

func versionSupported(v string) bool {
	for _, s := range supportedVersions {
		if s == v {
			return true
		}
	}
	return false
}

func validateMCPHeaders(r *http.Request, m map[string]any, ver string) string {
	method := asString(m["method"])
	hdrMethod := r.Header.Get("Mcp-Method")
	if ver == protocolModern {
		if protocolHeader(r) == "" {
			return "required header MCP-Protocol-Version is missing"
		}
		if hdrMethod == "" {
			return "required header Mcp-Method is missing"
		}
	}
	if hdrMethod != "" && hdrMethod != method {
		return "Mcp-Method header value '" + hdrMethod + "' does not match body value '" + method + "'"
	}
	nameHdr := decodeMCPHeader(r.Header.Get("Mcp-Name"))
	params, _ := m["params"].(map[string]any)
	var bodyName string
	if params != nil {
		bodyName = asString(params["name"])
		if bodyName == "" {
			bodyName = asString(params["uri"])
		}
	}
	if ver == protocolModern && method == "tools/call" && r.Header.Get("Mcp-Name") == "" {
		return "required header Mcp-Name is missing"
	}
	if nameHdr != "" && bodyName != "" && nameHdr != bodyName {
		return "Mcp-Name header value '" + nameHdr + "' does not match body value '" + bodyName + "'"
	}
	return ""
}

func originAllowed(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	host := u.Hostname()
	switch host {
	case "localhost", "127.0.0.1", "::1", "emailagent.hedwig.sh":
		return true
	}
	if strings.HasSuffix(host, ".hedwig.sh") {
		return true
	}
	reqHost := r.Host
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = h
	}
	if strings.EqualFold(host, reqHost) {
		return true
	}
	// DNS-rebinding guard: local-only bind rejects unknown Origins.
	if cfg.Host == "127.0.0.1" || cfg.Host == "localhost" || cfg.Host == "::1" {
		return false
	}
	return true
}


func handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !originAllowed(r) {
		writeJSON(w, 403, jsonRPCErr(nil, -32000, "Forbidden origin", nil))
		return
	}

	// Every JSON-RPC request dispatches; tools that need the caller's node
	// read the per-request Bearer identity inside the tool handler.
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB cap
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, 400, jsonRPCErr(nil, -32700, "failed to read body", nil))
			return
		}
		if len(bytes.TrimSpace(raw)) > 0 {
			if out, code, ok := dispatchJSONRPC(r, raw); ok {
				if code == http.StatusAccepted {
					w.Header().Set("Access-Control-Allow-Origin", "*")
					w.WriteHeader(http.StatusAccepted)
					return
				}
				writeJSON(w, code, out)
				return
			}
		}
	}
	writeJSON(w, 405, map[string]any{"error": "POST JSON-RPC to /mcp"})
}

func dispatchJSONRPC(r *http.Request, raw []byte) (any, int, bool) {
	var msgs any
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return jsonRPCErr(nil, -32700, "Parse error", nil), 400, true
	}
	var list []map[string]any
	switch v := msgs.(type) {
	case []any:
		for _, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				return jsonRPCErr(nil, -32600, "Invalid Request", nil), 400, true
			}
			list = append(list, m)
		}
	case map[string]any:
		list = []map[string]any{v}
	default:
		return jsonRPCErr(nil, -32600, "Invalid Request", nil), 400, true
	}
	if len(list) == 0 {
		return jsonRPCErr(nil, -32600, "Invalid Request", nil), 400, true
	}

	_, isBatch := msgs.([]any)
	out := make([]any, 0, len(list))
	httpStatus := 200
	allNotifications := true

	for _, m := range list {
		method := asString(m["method"])
		id, hasID := m["id"]
		if hasID {
			allNotifications = false
		}

		ver, mismatch := requestedVersion(r, m)
		if mismatch != "" {
			httpStatus = 400
			out = append(out, jsonRPCErr(id, -32020, "Header mismatch: "+mismatch, nil))
			continue
		}
		if msg := validateMCPHeaders(r, m, ver); msg != "" {
			httpStatus = 400
			out = append(out, jsonRPCErr(id, -32020, "Header mismatch: "+msg, nil))
			continue
		}
		if !versionSupported(ver) {
			httpStatus = 400
			out = append(out, jsonRPCErr(id, -32022, "Unsupported protocol version", map[string]any{
				"supported": supportedVersions, "requested": ver,
			}))
			continue
		}

		if !hasID {
			switch method {
			case "notifications/initialized", "notifications/cancelled":
				continue
			default:
				httpStatus = 400
				out = append(out, jsonRPCErr(nil, -32600, "notification "+method+" not accepted", nil))
				continue
			}
		}

		params, _ := m["params"].(map[string]any)
		if params == nil {
			params = map[string]any{}
		}

		switch method {
		case "server/discover":
			out = append(out, jsonRPCResult(id, discoverResult()))
		case "initialize":
			out = append(out, jsonRPCResult(id, initializeResult(ver)))
		case "tools/list":
			out = append(out, jsonRPCResult(id, toolsListResult()))
		case "tools/call":
			name := asString(params["name"])
			args, _ := params["arguments"].(map[string]any)
			if args == nil {
				args = map[string]any{}
			}
			if name == "" {
				out = append(out, jsonRPCErr(id, -32602, "Invalid params: missing tool name", nil))
				continue
			}
			res, err := callLexeTool(name, args, bearerLexe(r))
			if err != nil {
				if strings.HasPrefix(err.Error(), "unknown tool") {
					out = append(out, jsonRPCErr(id, -32602, err.Error(), nil))
					continue
				}
				out = append(out, jsonRPCResult(id, toolCallResult(map[string]any{"ok": false, "error": err.Error()}, true)))
				continue
			}
			out = append(out, jsonRPCResult(id, toolCallResult(res, false)))
		case "ping":
			if ver == protocolModern {
				httpStatus = 404
				out = append(out, jsonRPCErr(id, -32601, "Method not found: ping was removed in 2026-07-28", nil))
				continue
			}
			out = append(out, jsonRPCResult(id, map[string]any{}))
		default:
			out = append(out, jsonRPCErr(id, -32601, "method "+method+" not found", nil))
		}
	}

	if allNotifications && len(out) == 0 {
		return nil, http.StatusAccepted, true
	}
	if !isBatch {
		return out[0], httpStatus, true
	}
	return out, httpStatus, true
}


func main() {
	c := loadConfig()
	cfg = c
	TOOLS = buildTools()

	srv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:           router(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second, // request read only; tool waits happen after
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Printf("[lexe-mcp] shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	log.Printf("[lexe-mcp] MCP on http://%s:%d/mcp (Lexe gateway, network %s)",
		cfg.Host, cfg.Port, cfg.LexeNetwork)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[lexe-mcp] %v", err)
	}
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", handleMCP)
	mux.HandleFunc("/mcp/", handleMCP)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { health(w) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			health(w)
			return
		}
		writeJSON(w, 404, map[string]any{"error": "not found", "paths": []string{"/mcp", "/health"}})
	})
	return withCORS(mux)
}

func health(w http.ResponseWriter) {
	writeJSON(w, 200, map[string]any{
		"service": "lexe-mcp", "port": cfg.Port, "network": cfg.LexeNetwork,
	})
}
