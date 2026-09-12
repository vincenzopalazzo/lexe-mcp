// lexe-mcp — MCP server for Lexe Lightning (optional L402 hop).
// Single file, stdlib only.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"path/filepath"
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
	LexeSidecarURL        string
	AgenticMailURL        string
	AgenticMailMasterKey  string
	UpstreamMCPURL        string
	UpstreamMCPToken      string
	AmountSats            int
	PayMaxSats            int
	InvoiceDescription    string
	OfferTTL              int
	StateDir              string
	PublicURL             string
}

var cfg config

const (
	protocolModern = "2026-07-28"
	protocol202511 = "2025-11-25"
	protocol202503 = "2025-03-26"
	serverName     = "lexe-mcp"
	serverVersion  = "1.1.0"
)

var supportedVersions = []string{protocolModern, protocol202511, protocol202503}

const paywallInstructions = "Lexe Lightning MCP. Send Authorization: Bearer <Lexe SDK credentials> for invoice/payment tools. Optional L402 hop: unpaid non-discovery requests get HTTP 402 + a BOLT12 offer; after payment, X-PAYMENT or a minted ak_ token proxies upstream. Modern clients (2026-07-28) should call server/discover first."

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

func expandHome(p string) string {
	if p != "" && (p == "~" || strings.HasPrefix(p, "~/")) {
		home, err := os.UserHomeDir()
		if err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

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
	am, _ := file["agenticmail"].(map[string]any)

	c := config{
		Port:                  envIntOrFileInt("PORT", get("port"), 8010),
		Host:                  envOr("HOST", get("host")),
		LexeClientCredentials: envOr("LEXE_CLIENT_CREDENTIALS", get("lexeClientCredentials")),
		LexeSidecarURL:        strings.TrimRight(envOr("LEXE_SIDECAR_URL", get("lexeSidecarUrl")), "/"),
		AgenticMailURL: strings.TrimRight(envOr("AGENTICMAIL_URL", func() any {
			if am != nil {
				return am["url"]
			}
			return nil
		}()), "/"),
		AgenticMailMasterKey: envOr("AGENTICMAIL_MASTER_KEY", func() any {
			if am != nil {
				return am["masterKey"]
			}
			return nil
		}()),
		UpstreamMCPURL:     envOr("UPSTREAM_MCP_URL", get("upstreamMcpUrl")),
		UpstreamMCPToken:   envOr("UPSTREAM_MCP_TOKEN", get("upstreamMcpToken")),
		AmountSats:         envIntOrFileInt("L402_AMOUNT_SATS", get("amountSats"), 1),
		PayMaxSats:         envIntOrFileInt("LEXE_PAY_MAX_SATS", get("payMaxSats"), 0),
		InvoiceDescription: asString(get("invoiceDescription")),
		OfferTTL:           cfgInt(fmt.Sprintf("%v", get("offerTtlSecs")), 3600),
		StateDir:           expandHome(asString(get("stateDir"))),
		PublicURL:          strings.TrimRight(envOr("PUBLIC_URL", get("publicUrl")), "/"),
	}

	// defaults
	if c.Port == 0 {
		c.Port = 8010
	}
	if c.Host == "" {
		c.Host = "0.0.0.0"
	}
	if c.LexeSidecarURL == "" {
		c.LexeSidecarURL = "http://127.0.0.1:5393"
	}
	if c.AgenticMailURL == "" {
		c.AgenticMailURL = "http://127.0.0.1:3829"
	}
	if c.UpstreamMCPURL == "" {
		c.UpstreamMCPURL = "http://127.0.0.1:8014/mcp"
	}
	if c.AmountSats == 0 {
		c.AmountSats = 1
	}
	if c.InvoiceDescription == "" {
		c.InvoiceDescription = "AgenticMail MCP access"
	}
	if c.OfferTTL == 0 {
		c.OfferTTL = 3600
	}
	if c.StateDir == "" {
		c.StateDir = "~/.lexe-mcp"
	}

	if looksPlaceholder(c.LexeClientCredentials) {
		c.LexeClientCredentials = ""
		log.Printf("[lexe-mcp] no server-side lexeClientCredentials — clients must send Authorization: Bearer <Lexe SDK credentials>")
	}
	if c.AgenticMailMasterKey == "" {
		log.Printf("[lexe-mcp] no agenticmail.masterKey — per-client account mint disabled")
	}
	if c.UpstreamMCPToken == "" {
		log.Printf("[lexe-mcp] no upstreamMcpToken — L402 hop will proxy without MCP HTTP auth")
	}
	return c
}

// ---------- state ----------

type stateRec struct {
	Account   any    `json:"account"`
	Email     string `json:"email"`
	AK        string `json:"ak"`
	SettledAt string `json:"settledAt"`
}

var (
	stateMu   sync.Mutex
	STATE     = map[string]stateRec{}
	stateFile string
	saveTimer *time.Timer
)

func loadState() {
	data, err := os.ReadFile(stateFile)
	if err == nil {
		var m map[string]stateRec
		if err := json.Unmarshal(data, &m); err == nil {
			STATE = m
		}
	}
}

func persistState() {
	stateMu.Lock()
	defer stateMu.Unlock()
	data, _ := json.MarshalIndent(STATE, "", "  ")
	_ = os.WriteFile(stateFile, data, 0o644)
}

// saveState debounces persistence (250 ms).
func saveState() {
	stateMu.Lock()
	if saveTimer != nil {
		saveTimer.Stop()
	}
	saveTimer = time.AfterFunc(250*time.Millisecond, persistState)
	stateMu.Unlock()
}

// ---------- sidecar ----------

type httpError struct {
	msg string
}

func (e httpError) Error() string { return e.msg }

func sidecar(method, p string, body any, timeoutMs int, creds string) (any, error) {
	if creds == "" {
		creds = cfg.LexeClientCredentials
	}
	if creds == "" {
		return nil, httpError{"missing Lexe identity: send Authorization: Bearer <SDK client credentials>"}
	}
	url := cfg.LexeSidecarURL + p
	var reqBody io.Reader
	headers := map[string]string{
		"Authorization": "Bearer " + creds,
	}
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		headers["Content-Type"] = "application/json"
		reqBody = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	text, _ := io.ReadAll(resp.Body)
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
		return out, httpError{fmt.Sprintf("sidecar %s %s -> %d: %s", method, p, resp.StatusCode, s)}
	}
	return out, nil
}

// sidecarHealth: 5 s timeout, no auth. "server answered" = "sidecar up".
func sidecarHealth() (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", cfg.LexeSidecarURL+"/v2/health", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, httpError{fmt.Sprintf("sidecar /v2/health -> %d", resp.StatusCode)}
	}
	text, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(text) > 0 {
		_ = json.Unmarshal(text, &out)
	}
	if out == nil {
		out = map[string]any{}
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
	out, err := sidecar("POST", "/v2/node/create_offer", map[string]any{
		"description":     description,
		"min_amount":      strconv.Itoa(minAmountSats),
		"expiration_secs": ttl,
	}, 120000, creds)
	if err != nil {
		return nil, err
	}
	return asMap(out), nil
}

func getPayment(index string, creds string) (map[string]any, error) {
	out, err := sidecar("GET", "/v2/node/payment?index="+url.QueryEscape(index), nil, 120000, creds)
	if err != nil {
		return nil, err
	}
	return asMap(out), nil
}

func updatedPayments(creds string) (map[string]any, error) {
	out, err := sidecar("GET", "/v2/node/updated_payments", nil, 120000, creds)
	if err != nil {
		return nil, err
	}
	return asMap(out), nil
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

// pickLightningPayable prefers the sidecar's recommended Lightning route
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

func analyzePaymentString(paymentString, creds string) (map[string]any, error) {
	out, err := sidecar("GET", "/v2/node/analyze?payment_string="+url.QueryEscape(paymentString), nil, 30000, creds)
	if err != nil {
		return nil, err
	}
	m := asMap(out)
	if m == nil {
		return map[string]any{"raw": out}, nil
	}
	return m, nil
}

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
	var path string
	switch kind {
	case "invoice":
		path = "/v2/node/pay_invoice"
		body["invoice"] = raw
		if _, hasAmt := satsInt(picked["amount"]); !hasAmt {
			body["fallback_amount"] = strconv.Itoa(amt)
		}
	case "offer":
		path = "/v2/node/pay_offer"
		body["offer"] = raw
		body["amount"] = strconv.Itoa(amt)
	case "lnurl-pay", "lnurl":
		path = "/v2/node/pay_lnurl"
		body["lnurl"] = raw
		body["amount"] = strconv.Itoa(amt)
	default:
		return nil, httpError{"unsupported payable kind: " + kind}
	}
	out, err := sidecar("POST", path, body, 180000, creds)
	if err != nil {
		return nil, err
	}
	return asMap(out), nil
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
	body := map[string]any{"index": index}
	if proofNote != "" {
		body["proof_note"] = proofNote
	}
	out, err := sidecar("POST", "/v2/node/create_payer_proof", body, 30000, creds)
	if err != nil {
		return "", err
	}
	proof := firstString(asMap(out), "proof")
	if proof == "" {
		return "", httpError{"sidecar create_payer_proof returned no proof"}
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

// ---------- agenticmail ----------

func am(method, p string, body any) (map[string]any, error) {
	var reqBody io.Reader
	headers := map[string]string{
		"Authorization": "Bearer " + cfg.AgenticMailMasterKey,
	}
	if body != nil {
		b, _ := json.Marshal(body)
		headers["Content-Type"] = "application/json"
		reqBody = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, cfg.AgenticMailURL+p, reqBody)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	text, _ := io.ReadAll(resp.Body)
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
		return asMap(out), httpError{fmt.Sprintf("agenticmail %s %s -> %d: %s", method, p, resp.StatusCode, s)}
	}
	return asMap(out), nil
}

// accountForPayment mints (or reuses) the per-client account for a settled payment.
func accountForPayment(index string, payment any) (stateRec, error) {
	stateMu.Lock()
	existing := STATE[index]
	stateMu.Unlock()
	if existing.AK != "" {
		return existing, nil
	}

	idx := index
	if len(idx) > 12 {
		idx = idx[:12]
	}
	label := "client-" + idx
	email := label + "@users.hedwig.sh"
	amBody := map[string]any{
		"email":    email,
		"label":    label,
		"metadata": map[string]any{"source": "lexe-l402", "paymentIndex": index},
	}
	created, err := am("POST", "/api/v1/accounts", amBody)
	if err != nil {
		log.Printf("[lexe-mcp] create_account fallback: %v", err)
		created, err = am("POST", "/accounts", amBody)
		if err != nil {
			return stateRec{}, err
		}
	}

	// accept whatever shape — hunt for an api key
	ak := firstString(created, "apiKey", "api_key", "accessToken", "token", "key")
	if ak == "" {
		if acct := asMap(created["account"]); acct != nil {
			ak = firstString(acct, "apiKey", "api_key")
		}
	}
	if ak == "" {
		s := fmt.Sprintf("%v", created)
		if len(s) > 300 {
			s = s[:300]
		}
		return stateRec{}, httpError{"agenticmail create_account: no API key in response: " + s}
	}

	rec := stateRec{
		Account:   firstValue(created, "account"),
		Email:     email,
		AK:        ak,
		SettledAt: time.Now().UTC().Format(time.RFC3339),
	}
	if rec.Account == nil {
		rec.Account = created
	}
	stateMu.Lock()
	STATE[index] = rec
	stateMu.Unlock()
	saveState()
	log.Printf("[lexe-mcp] minted account %s for payment %s", email, index)
	return rec, nil
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func firstValue(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			return v
		}
	}
	return nil
}

// ---------- L402 core ----------

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

// bearerAk is a minted AgenticMail token (ak_…). Used to proxy upstream.
func bearerAk(r *http.Request) string {
	t := bearerToken(r)
	if t != "" && strings.HasPrefix(t, "ak_") {
		return t
	}
	return ""
}

// bearerLexe is a Lexe SDK client-credentials blob. Used as the sidecar identity.
// Anything that is not an ak_ token is treated as a Lexe identity (portable
// client credentials are a long base64 string, not ak_…).
func bearerLexe(r *http.Request) string {
	t := bearerToken(r)
	if t == "" || strings.HasPrefix(t, "ak_") {
		return ""
	}
	return t
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

// 402 response body — L402 "accepts" style, bolt12 scheme.
func paymentRequired(w http.ResponseWriter, reason string) {
	if reason == "" {
		reason = "payment_required"
	}
	if cfg.LexeClientCredentials == "" {
		writeJSON(w, 503, map[string]any{
			"error":  "L402 hop has no Lexe identity — set lexeClientCredentials (SDK client from the Lexe app) on the server",
			"reason": reason,
		})
		return
	}
	offer, err := createOffer(cfg.InvoiceDescription, cfg.AmountSats, nil, "")
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error()})
		return
	}
	bolt12 := firstString(offer, "offer", "bolt12")
	if bolt12 == "" {
		if inner := asMap(offer["offer"]); inner != nil {
			bolt12 = firstString(inner, "bolt12")
		}
	}
	if bolt12 == "" {
		s := fmt.Sprintf("%v", offer)
		if len(s) > 300 {
			s = s[:300]
		}
		writeJSON(w, 502, map[string]any{"error": "sidecar create_offer returned no offer: " + s})
		return
	}
	pub := cfg.PublicURL
	if pub == "" {
		pub = fmt.Sprintf("http://%s:%d", cfg.Host, cfg.Port)
	}
	body := map[string]any{
		"version":             "0.2.2",
		"scheme":              "bolt12",
		"network":             "lightning",
		"amount_sats":         cfg.AmountSats,
		"currency":            "sats",
		"offer":               bolt12,
		"description":         cfg.InvoiceDescription,
		"pay_to":              "emailagent.hedwig.sh",
		"reason":              reason,
		"retry_after_secs":    10,
		"payment_request_url": pub + "/mcp",
		"instructions":        "Pay the BOLT12 offer (lno1…) with any Lightning wallet that supports offers, then resend this request with header X-PAYMENT: <payment index> (lexe.check_payment). Discovery methods (initialize, server/discover, tools/list, lexe.*) stay unpaid.",
		"offers": []map[string]any{
			{
				"id":              "bolt12-access",
				"title":           "AgenticMail MCP access",
				"description":     cfg.InvoiceDescription,
				"type":            "one-time",
				"amount":          cfg.AmountSats,
				"currency":        "sats",
				"payment_methods": []string{"lightning"},
				"bolt12":          bolt12,
			},
		},
		"payment_request": map[string]any{
			"bolt12_offer": bolt12,
		},
	}
	writeJSON(w, 402, body, map[string]string{
		"WWW-Authenticate": `L402 scheme="bolt12"`,
	})
}

// verifyProof: verify an X-PAYMENT proof (payment index).
type proofResult struct {
	OK      bool
	Account stateRec
	Payment any
	Error   string
}

func verifyProof(r *http.Request) proofResult {
	proof := r.Header.Get("X-PAYMENT")
	if proof == "" {
		proof = r.Header.Get("X-PAYMENT-PROOF")
	}
	if proof == "" {
		return proofResult{Error: "missing X-PAYMENT header"}
	}
	index := strings.TrimSpace(strings.TrimPrefix(proof, "index="))
	payment, err := getPayment(index, "")
	if err != nil {
		return proofResult{Error: "payment lookup failed: " + err.Error()}
	}
	if !paymentSettled(payment) {
		st := asString(payment["status"])
		if st == "" {
			st = "unknown"
		}
		return proofResult{Error: "payment not settled yet (status=" + st + ") — retry in a few seconds"}
	}
	amt, ok := amountSats(payment)
	if ok && amt < float64(cfg.AmountSats) {
		return proofResult{Error: fmt.Sprintf("underpaid: %v < %d sats", amt, cfg.AmountSats)}
	}
	account, err := accountForPayment(index, payment)
	if err != nil {
		return proofResult{Error: "account mint failed: " + err.Error()}
	}
	return proofResult{OK: true, Account: account, Payment: payment}
}

// amountSats mirrors: Number(payment.amount ?? payment.amount_msats / 1000 ?? NaN)
func amountSats(p map[string]any) (float64, bool) {
	if v, ok := p["amount"]; ok {
		if f, ok2 := toFloat(v); ok2 {
			return f, true
		}
	}
	if v, ok := p["amount_msats"]; ok {
		if f, ok2 := toFloat(v); ok2 {
			return f / 1000, true
		}
	}
	return 0, false
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// ---------- upstream proxy ----------

var hopSkip = map[string]bool{
	"host": true, "connection": true, "keep-alive": true,
	"proxy-authorization": true, "authorization": true,
	"te": true, "trailer": true, "transfer-encoding": true,
	"upgrade": true, "proxy-connection": true,
}

func hopHeaders(r *http.Request, _ string) http.Header {
	h := http.Header{}
	for k, vs := range r.Header {
		if hopSkip[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	// Upstream agenticmail-mcp authenticates the HTTP transport with a
	// static MCP token, not the per-client AgenticMail ak_. Always use
	// the configured hop token when proxying.
	if cfg.UpstreamMCPToken != "" {
		h.Set("Authorization", "Bearer "+cfg.UpstreamMCPToken)
	}
	if h.Get("Accept") == "" {
		h.Set("Accept", "application/json, text/event-stream")
	}
	return h
}

func proxyUpstream(r *http.Request, w http.ResponseWriter, accountAk string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": "read body: " + err.Error()})
		return
	}
	var reqBody io.Reader
	if r.Method != "GET" && r.Method != "HEAD" {
		reqBody = bytes.NewReader(body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	up, err := http.NewRequestWithContext(ctx, r.Method, cfg.UpstreamMCPURL, reqBody)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": "new request: " + err.Error()})
		return
	}
	up.Header = hopHeaders(r, accountAk)
	resp, err := http.DefaultClient.Do(up)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": "upstream: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// ---------- MCP tools ----------

var TOOLS []map[string]any

func buildTools() []map[string]any {
	return []map[string]any{
		{
			"name":        "lexe.create_invoice",
			"title":       "Create Lightning invoice",
			"description": "Create a fresh BOLT12 offer (reusable, min amount in sats). Pay it with any Lightning wallet; keep the returned offer string to pay, and remember the payment index your wallet reports.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"description": map[string]any{"type": "string", "description": "Invoice description (<=200 chars)"},
					"amount_sats": map[string]any{"type": "number", "description": "Min amount in sats (default " + fmt.Sprintf("%d", cfg.AmountSats) + ")"},
				},
			},
		},
		{
			"name":        "lexe.check_payment",
			"title":       "Check Lightning payment",
			"description": "Check whether a payment (by index) has settled. After settlement call lexe.my_account to get your MCP Bearer token, or resend /mcp with X-PAYMENT: <index>.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"index": map[string]any{"type": "string", "description": "Payment index from your wallet"},
				},
				"required": []string{"index"},
			},
		},
		{
			"name":        "lexe.my_account",
			"title":       "Minted AgenticMail account",
			"description": "Return the AgenticMail account + Bearer token (ak_…) minted for a settled payment index.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"index": map[string]any{"type": "string", "description": "Payment index"},
				},
				"required": []string{"index"},
			},
		},
		{
			"name":        "lexe.node_health",
			"title":       "Lexe node health",
			"description": "Lexe sidecar / node health.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "lexe.analyze",
			"title":       "Analyze invoice or offer",
			"description": "Decode a BOLT11 invoice (lnbc…), BOLT12 offer (lno1…), or Lightning Address without sending. Returns amount/kind so you can inspect before lexe.pay.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"invoice":        map[string]any{"type": "string", "description": "BOLT11 invoice, BOLT12 offer, or Lightning Address"},
					"offer":          map[string]any{"type": "string", "description": "Alias for invoice when the string is a BOLT12 offer"},
					"payment_string": map[string]any{"type": "string", "description": "Alias for invoice"},
				},
			},
		},
		{
			"name":        "lexe.pay",
			"title":       "Pay invoice or offer",
			"description": "Pay a Lightning invoice or offer from the caller's Lexe node. Pass the BOLT11 (lnbc…) or BOLT12 (lno1…) string. Amountless strings need amount_sats. On-chain addresses are refused. After a settled BOLT12 offer pay, also returns a payer proof (lnp1…) and proof_url on lnproof.space.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"invoice":     map[string]any{"type": "string", "description": "BOLT11 invoice (lnbc…) or BOLT12 offer (lno1…). Lightning Address also works."},
					"offer":       map[string]any{"type": "string", "description": "Alias for invoice when paying a BOLT12 offer"},
					"amount_sats": map[string]any{"type": "number", "description": "Sats to send. Required if the invoice/offer has no amount. Must match a fixed invoice amount."},
					"note":        map[string]any{"type": "string", "description": "Personal note stored locally, not sent to the receiver (<=200 chars)"},
					"proof_note":  map[string]any{"type": "string", "description": "Optional public note bound into a BOLT12 payer proof (offer pays only, <=200 chars)"},
				},
			},
		},
	}
}

// callLexeTool dispatches one MCP tool call to the Lexe sidecar / AgenticMail.
// creds is the per-request Lexe SDK identity (empty → server config fallback).
func callLexeTool(name string, args map[string]any, creds string) (any, error) {
	switch name {
	case "lexe.create_invoice":
		desc := asString(args["description"])
		amt := cfgInt(args["amount_sats"], cfg.AmountSats)
		if amt == 0 {
			amt = cfg.AmountSats
		}
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
		p, err := getPayment(asString(args["index"]), creds)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "settled": paymentSettled(p), "payment": p}, nil
	case "lexe.my_account":
		idx := asString(args["index"])
		p, err := getPayment(idx, creds)
		if err != nil {
			return nil, err
		}
		if !paymentSettled(p) {
			return map[string]any{"ok": false, "error": "payment not settled yet"}, nil
		}
		a, err := accountForPayment(idx, p)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "email": a.Email, "bearer_token": a.AK}, nil
	case "lexe.node_health":
		h, err := sidecarHealth()
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "health": h}, nil
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
		idx := firstString(p, "index")
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
		"instructions":      paywallInstructions,
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
		"instructions":    paywallInstructions,
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

func isFreeMethod(m string) bool {
	switch m {
	case "server/discover", "initialize", "notifications/initialized",
		"notifications/cancelled", "tools/list", "tools/call", "ping":
		return true
	}
	return false
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

	// 1. minted account bearer token -> straight proxy.
	if ak := bearerAk(r); ak != "" {
		proxyUpstream(r, w, ak)
		return
	}

	// 2. payment proof header -> verify, then proxy.
	if r.Header.Get("X-PAYMENT") != "" || r.Header.Get("X-PAYMENT-PROOF") != "" {
		v := verifyProof(r)
		if v.OK {
			proxyUpstream(r, w, v.Account.AK)
			return
		}
		body := map[string]any{"reason": "proof_rejected", "error": v.Error, "retry_after_secs": 10}
		if strings.HasPrefix(v.Error, "payment not settled") {
			if offer, err := createOffer(cfg.InvoiceDescription, cfg.AmountSats, nil, ""); err == nil {
				b := firstString(offer, "offer", "bolt12")
				if b == "" {
					b = firstString(asMap(offer["offer"]), "bolt12")
				}
				if b != "" {
					body["offer"] = b
				}
			}
		}
		writeJSON(w, 402, body)
		return
	}

	// 3. no credentials — allow discovery + Lexe paywall tools without payment.
	if r.Method == http.MethodPost {
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

	// 4. otherwise: fresh BOLT12 offer (L402).
	paymentRequired(w, "")
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

	hasFree := false
	for _, m := range list {
		if isFreeMethod(asString(m["method"])) {
			hasFree = true
			break
		}
	}
	if !hasFree {
		return nil, 0, false
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
			out = append(out, jsonRPCErr(id, -32601, "method "+method+" requires payment", nil))
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

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var ev map[string]any
	_ = json.Unmarshal(body, &ev)
	if idx := asString(ev["index"]); idx != "" {
		if _, err := accountForPayment(idx, ev); err != nil {
			log.Printf("[lexe-mcp] webhook mint: %v", err)
		}
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(200)
	_, _ = w.Write([]byte("ok"))
}

func main() {
	c := loadConfig()
	cfg = c
	TOOLS = buildTools()
	stateDir := cfg.StateDir
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		log.Fatalf("[lexe-mcp] mkdir %s: %v", stateDir, err)
	}
	stateFile = filepath.Join(stateDir, "payments.json")
	loadState()
	defer persistState()

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler: router(),
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Printf("[lexe-mcp] shutting down, persisting state")
		persistState()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	log.Printf("[lexe-mcp] MCP on http://%s:%d/mcp (sidecar %s, L402 amount %d sats, upstream %s)",
		cfg.Host, cfg.Port, cfg.LexeSidecarURL, cfg.AmountSats, cfg.UpstreamMCPURL)
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
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleWebhook(w, r)
			return
		}
		writeJSON(w, 404, map[string]any{"error": "not found", "paths": []string{"/mcp", "/health", "/webhook"}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			health(w)
			return
		}
		writeJSON(w, 404, map[string]any{"error": "not found", "paths": []string{"/mcp", "/health", "/webhook"}})
	})
	return withCORS(mux)
}

func health(w http.ResponseWriter) {
	sidecarUp := false
	if _, err := sidecarHealth(); err == nil {
		sidecarUp = true
	}
	writeJSON(w, 200, map[string]any{
		"service": "lexe-mcp", "sidecar_up": sidecarUp, "port": cfg.Port, "amount_sats": cfg.AmountSats,
	})
}
