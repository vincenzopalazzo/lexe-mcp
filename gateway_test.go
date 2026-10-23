// SPDX-License-Identifier: Apache-2.0
package main

// Hermetic integration tests for the direct Lexe gateway client: a fake
// gateway (outer TLS pinned to a test CA, CONNECT with Proxy-Authorization)
// fronting a fake user node (inner mTLS: eph-CA-signed server certificate,
// client certificate required). Pins the wire protocol end to end.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeStack struct {
	gwAddr   string
	caPool   *x509.CertPool
	blob     string // SDK credentials blob valid for this stack
	mu       sync.Mutex
	gotProxy string
	payPolls int
	lastBody map[string]any
	lastPath string
	reqs     []string
	// history, when set, is the full payment list in updated_at order.
	// GET /user/v1/payments/updated pages it. The invoice-poll prefix
	// still returns the single pay_invoice fixture.
	history []any
}

func (f *fakeStack) record(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	f.mu.Lock()
	f.lastBody, f.lastPath = m, r.URL.Path
	f.mu.Unlock()
}

func newFakeStack(t *testing.T) *fakeStack {
	t.Helper()

	// --- CAs ---
	_, gwCAKey, err0 := ed25519.GenerateKey(rand.Reader)
	if err0 != nil {
		t.Fatal(err0)
	}
	gwCA := selfSign(t, big.NewInt(1), "test gateway CA", gwCAKey)
	_, ephKey, _ := ed25519.GenerateKey(rand.Reader)
	ephCA := selfSign(t, big.NewInt(2), "test eph CA", ephKey)

	// --- gateway server cert (signed by gateway CA, IP SAN) ---
	_, gwKey, _ := ed25519.GenerateKey(rand.Reader)
	gwCert := sign(t, big.NewInt(3), "gateway", gwKey, gwCA, gwCAKey, func(c *x509.Certificate) {
		c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	})

	// --- node server cert signed by the EPHEMERAL CA (like the real node) ---
	_, nodeKey, _ := ed25519.GenerateKey(rand.Reader)
	nodeCert := sign(t, big.NewInt(4), "run.lexe.app", nodeKey, ephCA, ephKey, func(c *x509.Certificate) {
		c.DNSNames = []string{"run.lexe.app"}
	})

	// --- client (revocable) cert signed by the eph CA ---
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	clientCert := sign(t, big.NewInt(5), "sdk client", clientKey, ephCA, ephKey, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	})

	fs := &fakeStack{}

	// --- fake node: inner mTLS server ---
	nodeMux := http.NewServeMux()
	nodeMux.HandleFunc("/user/v1/pay_offer", func(w http.ResponseWriter, r *http.Request) {
		fs.record(r)
		writeTestJSON(w, map[string]any{"created_at": 123})
	})
	nodeMux.HandleFunc("/user/v1/pay_invoice", func(w http.ResponseWriter, r *http.Request) {
		fs.record(r)
		writeTestJSON(w, map[string]any{"created_at": 456})
	})
	nodeMux.HandleFunc("/user/v1/payments/updated", func(w http.ResponseWriter, r *http.Request) {
		start := r.URL.Query().Get("start_index")
		fs.mu.Lock()
		history := fs.history
		fs.mu.Unlock()
		if history != nil && !strings.HasPrefix(start, "u0000000000000000455-") {
			limit := paymentsFetchLimit
			if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
				limit = n
			}
			out := make([]any, 0, limit)
			for _, item := range history {
				idx := paymentUpdatedIndex(asMap(item))
				if start != "" && (idx == "" || idx <= start) {
					continue
				}
				out = append(out, item)
				if len(out) >= limit {
					break
				}
			}
			writeTestJSON(w, map[string]any{"payments": out})
			return
		}
		if !strings.HasPrefix(start, "u0000000000000000455-") {
			writeTestJSON(w, map[string]any{"payments": []any{}})
			return
		}
		writeTestJSON(w, map[string]any{"payments": []any{map[string]any{
			"id": "ln_abc", "status": "completed", "created_at": 456,
			"direction": "outbound", "kind": "invoice", "amount": "1000",
			"updated_at": 456,
		}}})
	})
	nodeMux.HandleFunc("/user/v1/payments/id", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		fs.mu.Lock()
		fs.payPolls++
		n := fs.payPolls
		fs.mu.Unlock()
		if n < 2 { // first poll(s): registration not yet visible
			writeTestJSON(w, map[string]any{"maybe_payment": nil})
			return
		}
		writeTestJSON(w, map[string]any{"maybe_payment": map[string]any{
			"id": id, "status": "completed", "created_at": 123,
			"direction": "outbound", "kind": "offer", "amount": "21",
		}})
	})
	nodeMux.HandleFunc("/user/v1/create_payer_proof", func(w http.ResponseWriter, r *http.Request) {
		fs.record(r)
		writeTestJSON(w, map[string]any{"proof": "lnp1testproof"})
	})
	nodeMux.HandleFunc("/user/v1/create_offer", func(w http.ResponseWriter, r *http.Request) {
		fs.record(r)
		writeTestJSON(w, map[string]any{"offer": "lno1fakeoffer"})
	})
	nodeMux.HandleFunc("/user/v2/node_info", func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, map[string]any{"version": "0.9.12", "num_peers": 3})
	})

	nodeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ephPool := x509.NewCertPool()
	ephPool.AddCert(ephCA.cert)
	go func() {
		_ = (&http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fs.mu.Lock()
			fs.reqs = append(fs.reqs, r.Method+" "+r.URL.Path)
			fs.mu.Unlock()
			nodeMux.ServeHTTP(w, r)
		})}).Serve(tls.NewListener(nodeLn, &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{nodeCert.raw}, PrivateKey: nodeKey}},
			ClientAuth:   tls.RequireAndVerifyClientCert, // forces the client cert
			ClientCAs:    ephPool,                        // forces eph-CA-signed client
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"},
		}))
	}()

	// --- fake gateway: outer TLS server that tunnels CONNECT to the node ---
	gwHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "not a CONNECT", 400)
			return
		}
		auth := r.Header.Get("Proxy-Authorization")
		if auth != "Bearer dGVzdHRva2Vu" { // literal lexe_auth_token value
			w.WriteHeader(407)
			return
		}
		fs.mu.Lock()
		fs.gotProxy = auth
		fs.mu.Unlock()
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("gateway conn not hijackable")
			w.WriteHeader(500)
			return
		}
		clientConn, _, err := hj.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer clientConn.Close()
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			t.Error(err)
			return
		}
		nodeConn, err := net.Dial("tcp", nodeLn.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		defer nodeConn.Close()
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(nodeConn, clientConn); done <- struct{}{} }()
		go func() { _, _ = io.Copy(clientConn, nodeConn); done <- struct{}{} }()
		<-done
	})
	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = (&http.Server{Handler: gwHandler}).Serve(tls.NewListener(gwLn, &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{gwCert.raw}, PrivateKey: gwKey}},
			MinVersion:   tls.VersionTLS12,
		}))
	}()

	// --- credentials blob (base64 JSON, hex DER fields) ---
	pkcs8, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	credJSON, _ := json.Marshal(map[string]any{
		"user_pk":             strings.Repeat("ab", 32),
		"client_pk":           hex.EncodeToString([]byte("clientpk")),
		"rev_client_key_der":  hex.EncodeToString(pkcs8),
		"rev_client_cert_der": hex.EncodeToString(clientCert.raw),
		"eph_ca_cert_der":     hex.EncodeToString(ephCA.raw),
		"lexe_auth_token":     "dGVzdHRva2Vu", // base64("testtoken")
	})
	fs.blob = base64.StdEncoding.EncodeToString(credJSON)

	fs.gwAddr = gwLn.Addr().String()
	pool := x509.NewCertPool()
	pool.AddCert(gwCA.cert)
	fs.caPool = pool
	return fs
}

type testCert struct {
	cert *x509.Certificate
	raw  []byte
}

func selfSign(t *testing.T, sn *big.Int, cn string, key ed25519.PrivateKey) *testCert {
	tpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: cn}, IsCA: true, BasicConstraintsValid: true}
	return createCert(t, tpl, tpl, key.Public().(ed25519.PublicKey), key)
}

func sign(t *testing.T, sn *big.Int, cn string, key ed25519.PrivateKey, parent *testCert, parentKey ed25519.PrivateKey, mod func(*x509.Certificate)) *testCert {
	tpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: cn}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if mod != nil {
		mod(tpl)
	}
	return createCert(t, tpl, parent.cert, key.Public().(ed25519.PublicKey), parentKey)
}

func createCert(t *testing.T, tpl, parent *x509.Certificate, pub ed25519.PublicKey, signer ed25519.PrivateKey) *testCert {
	t.Helper()
	tpl.NotBefore = time.Now().Add(-time.Hour)
	tpl.NotAfter = time.Now().Add(time.Hour)
	raw, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{cert: cert, raw: raw}
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// withFakeStack swaps the gateway dial target + CA pool for a fake stack.
func withFakeStack(t *testing.T, fn func(t *testing.T, fs *fakeStack)) {
	t.Helper()
	fs := newFakeStack(t)
	oldCfg, oldAddr, oldPool := cfg, gatewayAddr, gatewayCAPool
	cfg = config{LexeNetwork: "mainnet", PayMaxSats: 0, InvoiceDescription: "d", OfferTTL: 3600}
	gatewayAddr = func() string { return fs.gwAddr }
	gatewayCAPool = func() *x509.CertPool { return fs.caPool }
	t.Cleanup(func() {
		cfg, gatewayAddr, gatewayCAPool = oldCfg, oldAddr, oldPool
	})
	fn(t, fs)
}

func TestParseLexeCreds(t *testing.T) {
	fs := newFakeStack(t)
	lc, err := parseLexeCreds(fs.blob)
	if err != nil {
		t.Fatal(err)
	}
	if lc.proxyToken == "" || lc.clientCert.PrivateKey == nil || lc.ephCA == nil {
		t.Fatalf("incomplete creds: %+v", lc)
	}
	if _, err := parseLexeCreds(fs.blob + "=="); err != nil { // padded exports
		t.Fatalf("padded blob: %v", err)
	}
	if _, err := parseLexeCreds("garbage!"); err == nil {
		t.Fatal("expected parse error for garbage")
	}
}

func TestGatewayPayOfferFlow(t *testing.T) {
	withFakeStack(t, func(t *testing.T, fs *fakeStack) {
		picked := map[string]any{"kind": "offer", "offer": "lno1fakeoffer"}
		p, err := sendLightningPay(picked, 21, "mynote", fs.blob)
		if err != nil {
			t.Fatal(err)
		}
		if asString(p["status"]) != "completed" {
			t.Fatalf("status = %v", p["status"])
		}
		if fs.gotProxy != "Bearer dGVzdHRva2Vu" {
			t.Fatalf("proxy auth = %q", fs.gotProxy)
		}
		// pay_offer body: sats amount, client-generated cid, note
		fs.mu.Lock()
		body, path := fs.lastBody, fs.lastPath
		fs.mu.Unlock()
		if path != "/user/v1/pay_offer" {
			t.Fatalf("path = %q", path)
		}
		if body["amount"] != "21" || body["offer"] != "lno1fakeoffer" || body["personal_note"] != "mynote" {
			t.Fatalf("pay_offer body: %#v", body)
		}
		if cid, _ := body["cid"].(string); len(cid) != 64 {
			t.Fatalf("cid = %v", body["cid"])
		}

		idx := paymentIndex(toInt64(p["created_at"]), asString(p["id"]))
		if !strings.HasPrefix(idx, "0000000000000000123-fs_") {
			t.Fatalf("index = %q", idx)
		}

		got, err := getPayment(idx, fs.blob)
		if err != nil || !paymentSettled(got) {
			t.Fatalf("check_payment: %v %v", got, err)
		}

		proof, err := createPayerProof(idx, "", fs.blob)
		if err != nil || proof != "lnp1testproof" {
			t.Fatalf("proof: %q %v", proof, err)
		}
		if payerProofLink(proof) != "https://lnproof.space/lnp1testproof" {
			t.Fatalf("proof_url: %q", payerProofLink(proof))
		}
	})
}

func TestGatewayPayInvoiceFlow(t *testing.T) {
	withFakeStack(t, func(t *testing.T, fs *fakeStack) {
		picked := map[string]any{"kind": "invoice", "invoice": "lnbc1amountless"} // amountless
		p, err := sendLightningPay(picked, 1000, "", fs.blob)
		if err != nil {
			t.Fatal(err)
		}
		if asString(p["status"]) != "completed" || asString(p["id"]) != "ln_abc" {
			t.Fatalf("payment: %#v", p)
		}
		fs.mu.Lock()
		body, path := fs.lastBody, fs.lastPath
		fs.mu.Unlock()
		if path != "/user/v1/pay_invoice" {
			t.Fatalf("path = %q", path)
		}
		if body["invoice"] != "lnbc1amountless" || body["fallback_amount"] != "1000" {
			t.Fatalf("pay_invoice body: %#v", body)
		}
	})
}

func TestGatewayCreateOfferAndNodeInfo(t *testing.T) {
	withFakeStack(t, func(t *testing.T, fs *fakeStack) {
		out, err := createOffer("desc", 21, nil, fs.blob)
		if err != nil {
			t.Fatal(err)
		}
		if firstString(out, "offer") != "lno1fakeoffer" {
			t.Fatalf("offer: %#v", out)
		}
		fs.mu.Lock()
		body, path := fs.lastBody, fs.lastPath
		fs.mu.Unlock()
		if path != "/user/v1/create_offer" || body["min_amount"] != "21" || body["description"] != "desc" {
			t.Fatalf("create_offer: %s %#v", path, body)
		}

		ni, err := nodeCall("GET", "/user/v2/node_info", nil, 5000, fs.blob)
		if err != nil {
			t.Fatal(err)
		}
		if asMap(ni)["version"] != "0.9.12" {
			t.Fatalf("node_info: %#v", ni)
		}
	})
}

func TestGatewayBadIdentity(t *testing.T) {
	withFakeStack(t, func(t *testing.T, fs *fakeStack) {
		if _, err := nodeCall("GET", "/user/v2/node_info", nil, 5000, "Zm9v"); err == nil ||
			!strings.Contains(err.Error(), "SDK credentials") {
			t.Fatalf("expected creds parse error, got %v", err)
		}
		// credentials valid for a DIFFERENT stack: the proxy token is the
		// same literal here, so the inner eph-CA pinning must reject it.
		other := newFakeStack(t)
		_, err := nodeCall("GET", "/user/v2/node_info", nil, 5000, other.blob)
		if err == nil || !strings.Contains(err.Error(), "ephemeral CA") {
			t.Fatalf("expected eph-CA rejection, got %v", err)
		}
	})
}

func TestMissingIdentity(t *testing.T) {
	old := cfg
	cfg = config{}
	t.Cleanup(func() { cfg = old })
	_, err := nodeCall("GET", "/user/v2/node_info", nil, 5000, "")
	if err == nil || !strings.Contains(err.Error(), "missing Lexe identity") {
		t.Fatalf("got %v", err)
	}
}

func oceanHistory() []any {
	return []any{
		map[string]any{
			"id": "ln_ocean1", "direction": "inbound", "status": "completed", "kind": "invoice",
			"amount": "1000.5", "fees": "1",
			"created_at": int64(1700000001000), "finalized_at": int64(1700000001500), "updated_at": int64(1700000001500),
			"payer_note": "OCEAN lightning payout",
		},
		map[string]any{
			"id": "ln_coffee", "direction": "outbound", "status": "completed", "kind": "invoice",
			"amount": "21", "fees": "0",
			"created_at": int64(1700000002000), "finalized_at": int64(1700000002000), "updated_at": int64(1700000002000),
			"note": "coffee",
		},
		map[string]any{
			"id": "ln_ocean2", "direction": "inbound", "status": "pending", "kind": "invoice",
			"amount": "500", "fees": "0",
			"created_at": int64(1700000003000), "updated_at": int64(1700000003000),
			"payer_note": "OCEAN lightning payout",
		},
		map[string]any{
			"id": "ln_ocean3", "direction": "Inbound", "status": "completed", "kind": "offer",
			"amount": "2000", "fees": "2.5",
			"created_at": int64(1700000004000), "finalized_at": int64(1700000004500), "updated_at": int64(1700000004500),
			"message": "ocean lightning payout extra",
		},
		map[string]any{
			"id": "ln_other", "direction": "inbound", "status": "completed", "kind": "invoice",
			"amount": "9", "fee": "0",
			"created_at": int64(1700000005000), "finalized_at": int64(1700000005000), "updated_at": int64(1700000005000),
			"payer_note": "thanks", "personal_note": "not a pool payout",
		},
		map[string]any{
			"id": "ln_noted", "direction": "inbound", "status": "completed", "kind": "invoice",
			"amount": "0.5", "fees": "0",
			"created_at": int64(1700000006000), "finalized_at": int64(1700000006000), "updated_at": int64(1700000006000),
			"personal_note": "OCEAN lightning payout manual",
		},
	}
}

func TestListPaymentsReadOnlySummary(t *testing.T) {
	withFakeStack(t, func(t *testing.T, fs *fakeStack) {
		oldFetch, oldScan := paymentsFetchLimit, paymentsMaxScan
		paymentsFetchLimit = 2
		paymentsMaxScan = 10000
		t.Cleanup(func() {
			paymentsFetchLimit, paymentsMaxScan = oldFetch, oldScan
		})
		fs.mu.Lock()
		fs.history = oceanHistory()
		before := len(fs.reqs)
		fs.mu.Unlock()

		args := map[string]any{
			"direction":  "inbound",
			"status":     "completed",
			"payer_note": "OCEAN lightning payout",
			"summary":    true,
		}
		out, err := listPayments(args, fs.blob)
		if err != nil {
			t.Fatal(err)
		}
		if out["count"] != 3 || out["amount_sats"] != "3001" {
			t.Fatalf("summary = %#v", out)
		}
		if out["truncated"] != false {
			t.Fatalf("truncated = %#v", out["truncated"])
		}
		if _, ok := out["next_start_index"]; ok {
			t.Fatalf("history exhausted but next_start_index set: %#v", out)
		}
		if _, ok := out["payments"]; ok {
			t.Fatal("summary mode returned payments")
		}

		fs.mu.Lock()
		reqs := append([]string(nil), fs.reqs[before:]...)
		fs.mu.Unlock()
		if len(reqs) < 3 {
			t.Fatalf("expected multiple pages, got %v", reqs)
		}
		for _, req := range reqs {
			if req != "GET /user/v1/payments/updated" {
				t.Fatalf("list_payments called %q; only GET payments/updated is allowed", req)
			}
		}

		// since the third match (created_at 1700000004000) through the note-only one
		args["since"] = "2023-11-14T22:13:24Z" // 1700000004000
		out, err = listPayments(args, fs.blob)
		if err != nil {
			t.Fatal(err)
		}
		if out["count"] != 2 || out["amount_sats"] != "2000.5" {
			t.Fatalf("since summary = %#v", out)
		}
	})
}

func TestListPaymentsPageAndProject(t *testing.T) {
	withFakeStack(t, func(t *testing.T, fs *fakeStack) {
		oldFetch := paymentsFetchLimit
		paymentsFetchLimit = 2
		t.Cleanup(func() { paymentsFetchLimit = oldFetch })
		fs.mu.Lock()
		fs.history = oceanHistory()
		fs.mu.Unlock()

		out, err := listPayments(map[string]any{
			"direction":  "inbound",
			"status":     "completed",
			"payer_note": "ocean lightning payout",
			"limit":      1,
		}, fs.blob)
		if err != nil {
			t.Fatal(err)
		}
		pays, _ := out["payments"].([]map[string]any)
		if len(pays) != 1 || out["count"] != 1 {
			t.Fatalf("first page = %#v", out)
		}
		p := pays[0]
		if p["id"] != "ln_ocean1" || p["direction"] != "inbound" || p["status"] != "completed" {
			t.Fatalf("payment = %#v", p)
		}
		if p["amount_sats"] != "1000.5" || p["fees"] != "1" {
			t.Fatalf("amounts = %#v", p)
		}
		if p["payer_note"] != "OCEAN lightning payout" || p["note"] != "" {
			t.Fatalf("notes = %#v", p)
		}
		if p["created_at"] != int64(1700000001000) || p["finalized_at"] != int64(1700000001500) {
			t.Fatalf("times = %#v", p)
		}
		wantIdx := paymentIndex(1700000001000, "ln_ocean1")
		if p["index"] != wantIdx {
			t.Fatalf("index = %v want %s", p["index"], wantIdx)
		}
		next := asString(out["next_start_index"])
		if next == "" || !strings.HasPrefix(next, "u") {
			t.Fatalf("next_start_index = %q", next)
		}

		rest, err := listPayments(map[string]any{
			"direction":   "inbound",
			"status":      "completed",
			"payer_note":  "OCEAN lightning payout",
			"start_index": next,
		}, fs.blob)
		if err != nil {
			t.Fatal(err)
		}
		restPays, _ := rest["payments"].([]map[string]any)
		if rest["count"] != 2 || len(restPays) != 2 {
			t.Fatalf("rest = %#v", rest)
		}
		if restPays[0]["id"] != "ln_ocean3" || restPays[0]["payer_note"] != "ocean lightning payout extra" {
			t.Fatalf("alias message not projected: %#v", restPays[0])
		}
		if restPays[1]["id"] != "ln_noted" || restPays[1]["note"] != "OCEAN lightning payout manual" {
			t.Fatalf("personal_note not projected: %#v", restPays[1])
		}
	})
}

func TestListPaymentsScanCap(t *testing.T) {
	withFakeStack(t, func(t *testing.T, fs *fakeStack) {
		oldFetch, oldScan := paymentsFetchLimit, paymentsMaxScan
		paymentsFetchLimit = 2
		paymentsMaxScan = 3
		t.Cleanup(func() {
			paymentsFetchLimit, paymentsMaxScan = oldFetch, oldScan
		})
		fs.mu.Lock()
		fs.history = oceanHistory()
		fs.mu.Unlock()

		out, err := listPayments(map[string]any{"summary": true}, fs.blob)
		if err != nil {
			t.Fatal(err)
		}
		if out["truncated"] != true || out["scanned"] != 3 {
			t.Fatalf("cap = %#v", out)
		}
		if asString(out["next_start_index"]) == "" {
			t.Fatal("expected next_start_index when the scan cap stops early")
		}
		// Unfiltered summary of the first three rows: 1000.5 + 21 + 500.
		// ocean3 (2000) is past the cap.
		if out["count"] != 3 || out["amount_sats"] != "1521.5" {
			t.Fatalf("partial summary = %#v", out)
		}
	})
}
