// SPDX-License-Identifier: Apache-2.0
package main

import (
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestPayableFromArgs(t *testing.T) {
	if got := payableFromArgs(map[string]any{"invoice": " lnbc1abc "}); got != "lnbc1abc" {
		t.Fatalf("invoice: %q", got)
	}
	if got := payableFromArgs(map[string]any{"offer": "lno1xyz"}); got != "lno1xyz" {
		t.Fatalf("offer: %q", got)
	}
	if got := payableFromArgs(map[string]any{}); got != "" {
		t.Fatalf("empty: %q", got)
	}
}

func TestPickLightningPayable(t *testing.T) {
	picked, err := pickLightningPayable(map[string]any{
		"payables": []any{
			map[string]any{"kind": "onchain", "onchain": "bc1qexample"},
			map[string]any{"kind": "offer", "offer": "lno1abc", "amount": "21"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if asString(picked["offer"]) != "lno1abc" {
		t.Fatalf("picked %#v", picked)
	}

	_, err = pickLightningPayable(map[string]any{
		"payables": []any{map[string]any{"kind": "onchain", "onchain": "bc1q"}},
	})
	if err == nil {
		t.Fatal("expected on-chain refusal")
	}

	_, err = pickLightningPayable(map[string]any{
		"payables":   []any{},
		"claimables": []any{map[string]any{"kind": "lnurl-withdraw"}},
	})
	if err == nil {
		t.Fatal("expected withdraw refusal")
	}
}

func TestResolvePayAmount(t *testing.T) {
	fixed := map[string]any{"amount": "1000"}
	amt, err := resolvePayAmount(fixed, 0, 0)
	if err != nil || amt != 1000 {
		t.Fatalf("fixed: amt=%d err=%v", amt, err)
	}
	if _, err := resolvePayAmount(fixed, 500, 0); err == nil {
		t.Fatal("expected mismatch")
	}
	if _, err := resolvePayAmount(map[string]any{}, 0, 0); err == nil {
		t.Fatal("expected amountless error")
	}
	amt, err = resolvePayAmount(map[string]any{"min_amount": "1", "max_amount": "5000"}, 21, 0)
	if err != nil || amt != 21 {
		t.Fatalf("amountless with explicit: amt=%d err=%v", amt, err)
	}
	if _, err := resolvePayAmount(fixed, 0, 100); err == nil {
		t.Fatal("expected max_sats")
	}
}

func TestPayerProofLink(t *testing.T) {
	proof := "lnp1pgd9xatswphhyapq"
	got := payerProofLink(" " + proof + " ")
	want := "https://lnproof.space/" + proof
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if payerProofLink("lnbc1notaproof") != "" {
		t.Fatal("expected empty for non-lnp")
	}
	if payerProofLink("") != "" {
		t.Fatal("expected empty for empty")
	}
}

// ---------- v2: local analysis ----------

func TestClassifyPayable(t *testing.T) {
	cases := []struct {
		in   string
		kind string
	}{
		{"lnbc10u1pxyz", "invoice"}, // 1000 sats
		{"lntb1qxyz", "invoice"},    // testnet amountless
		{"LNBC1M1XYZ", "invoice"},   // uppercase hrpart
		{"lno1qxyz", "offer"},       // BOLT12
		{"lnurl1dp68gurn8ghjum9vdjj", "lnurl-pay"},
		{"user@domain.com", "lnurl-pay"},  // lightning address
		{"bc1qexampleaddress", "onchain"}, // bech32
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "onchain"},
	}
	for _, c := range cases {
		_, kind := classifyPayable(c.in)
		if kind != c.kind {
			t.Errorf("classifyPayable(%q) = %q, want %q", c.in, kind, c.kind)
		}
	}
	if _, kind := classifyPayable("hello world"); kind != "" {
		t.Errorf("garbage classified as %q", kind)
	}
}

func TestBolt11AmountSats(t *testing.T) {
	cases := []struct {
		in     string
		sats   int
		hasAmt bool
	}{
		{"lnbc10u1px", 1000, true},        // 10 micro-BTC
		{"lnbc1m1px", 100000, true},       // 1 milli-BTC
		{"lnbc20n1px", 2, true},           // 20 nano-BTC
		{"lnbc1px", 0, false},             // amountless
		{"lnbc1p1px", 0, false},           // pico — sub-sat, treated amountless
		{"lnbc1231px", 12300000000, true}, // 123 BTC
		{"lntb5u1px", 500, true},          // testnet 5 micro
	}
	for _, c := range cases {
		sats, ok := bolt11AmountSats(c.in)
		if sats != c.sats || ok != c.hasAmt {
			t.Errorf("bolt11AmountSats(%q) = (%d, %v), want (%d, %v)", c.in, sats, ok, c.sats, c.hasAmt)
		}
	}
}

func TestAnalyzePaymentString(t *testing.T) {
	m, err := analyzePaymentString("lnbc10u1pabc", "")
	if err != nil {
		t.Fatal(err)
	}
	picked, err := pickLightningPayable(m)
	if err != nil {
		t.Fatal(err)
	}
	if asString(picked["kind"]) != "invoice" || asString(picked["invoice"]) != "lnbc10u1pabc" {
		t.Fatalf("picked %#v", picked)
	}
	amt, ok := satsInt(picked["amount"])
	if !ok || amt != 1000 {
		t.Fatalf("amount = %v", picked["amount"])
	}
	// on-chain → refusal
	if _, err := pickLightningPayable(mustAnalyze(t, "bc1qxyz")); err == nil {
		t.Fatal("expected on-chain refusal")
	}
}

func mustAnalyze(t *testing.T, s string) map[string]any {
	t.Helper()
	m, err := analyzePaymentString(s, "")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPaymentIDFromIndex(t *testing.T) {
	id, err := paymentIDFromIndex("0002683862736062841-ln_3ddcab")
	if err != nil || id != "ln_3ddcab" {
		t.Fatalf("got %q err %v", id, err)
	}
	if _, err := paymentIDFromIndex("nodash"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := paymentIDFromIndex("-leading"); err == nil {
		t.Fatal("expected error for leading dash")
	}
}

func TestPaymentIndex(t *testing.T) {
	got := paymentIndex(2683862736062841, "fs_ab")
	if len(got) != 19+1+len("fs_ab") || got[:19] != "0002683862736062841" {
		t.Fatalf("got %q", got)
	}
	if got != "0002683862736062841-fs_ab" {
		t.Fatalf("full: %q", got)
	}
}

func TestBolt11AmountBounds(t *testing.T) {
	// absurd magnitudes must not overflow into plausible amounts
	cases := []string{
		"lnbc99999999999999999999991px", // > maxSats digits
		"lnbc99999999999m1px",           // 1e11 * 1e5 sats = 1e16 > 2.1e15 cap
	}
	for _, c := range cases {
		if sats, ok := bolt11AmountSats(c); ok {
			t.Errorf("bolt11AmountSats(%q) = (%d, true), want rejected", c, sats)
		}
	}
	// boundary: exactly 21M BTC
	if sats, ok := bolt11AmountSats("lnbc21000000000m1px"); !ok || sats != 2100000000000000 {
		t.Fatalf("21M BTC = (%d, %v)", sats, ok)
	}
}

func TestProjectPaymentAliases(t *testing.T) {
	p := projectPayment(map[string]any{
		"id":            "ln_abc",
		"direction":     "Inbound",
		"status":        "Completed",
		"kind":          "Invoice",
		"amount":        "10.2500",
		"fee":           "0.125",
		"created_at":    int64(1700000001000),
		"finalized_at":  int64(1700000002000),
		"message":       "Hello Payer",
		"personal_note": "Mine",
	})
	if p["direction"] != "inbound" || p["status"] != "completed" || p["kind"] != "invoice" {
		t.Fatalf("labels = %#v", p)
	}
	if p["amount_sats"] != "10.25" || p["fees"] != "0.125" {
		t.Fatalf("amounts = %#v", p)
	}
	if p["payer_note"] != "Hello Payer" || p["note"] != "Mine" {
		t.Fatalf("notes = %#v", p)
	}
	if p["index"] != paymentIndex(1700000001000, "ln_abc") {
		t.Fatalf("index = %v", p["index"])
	}
	if p["finalized_at"] != int64(1700000002000) {
		t.Fatalf("finalized = %v", p["finalized_at"])
	}
}

func TestPaymentMatchesFilters(t *testing.T) {
	p := map[string]any{
		"direction":  "inbound",
		"status":     "completed",
		"created_at": int64(1700000001000),
		"payer_note": "OCEAN lightning payout",
		"note":       "keep",
		"amount":     "1000.5",
	}
	q, _, _, _, err := parsePaymentListArgs(map[string]any{
		"direction":  "inbound",
		"status":     "completed",
		"payer_note": "ocean LIGHTNING payout",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !paymentMatches(p, q) {
		t.Fatal("expected case-insensitive payer_note match")
	}
	noteOnly := map[string]any{
		"direction": "inbound", "status": "completed", "created_at": int64(1),
		"personal_note": "OCEAN lightning payout manual",
	}
	if !paymentMatches(noteOnly, q) {
		t.Fatal("expected note-field match")
	}
	out := map[string]any{"direction": "outbound", "status": "completed", "created_at": int64(1), "payer_note": "OCEAN lightning payout"}
	if paymentMatches(out, q) {
		t.Fatal("outbound should not match inbound filter")
	}
	pending := map[string]any{"direction": "inbound", "status": "pending", "created_at": int64(1), "payer_note": "OCEAN lightning payout"}
	if paymentMatches(pending, q) {
		t.Fatal("pending should not match completed filter")
	}

	since := int64(1700000002000)
	q.since = &since
	if paymentMatches(p, q) {
		t.Fatal("created_at before since should be excluded")
	}
}

func TestFormatSatsSum(t *testing.T) {
	sum := new(big.Rat)
	for _, s := range []string{"1000.5", "2000", "0.5"} {
		r, ok := parseSats(s)
		if !ok {
			t.Fatal(s)
		}
		sum.Add(sum, r)
	}
	if got := formatSats(sum); got != "3001" {
		t.Fatalf("sum = %s", got)
	}
	frac, ok := parseSats("1.2500")
	if !ok || formatSats(frac) != "1.25" {
		t.Fatalf("frac = %s ok=%v", formatSats(frac), ok)
	}
}

func TestParsePaymentListArgs(t *testing.T) {
	q, limit, summary, start, err := parsePaymentListArgs(map[string]any{
		"since":   "2026-10-23",
		"until":   "2026-10-23",
		"summary": "true",
		"status":  "paid",
		"limit":   500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !summary || limit != 200 || q.status != "completed" || start != "" {
		t.Fatalf("parsed summary=%v limit=%d status=%s", summary, limit, q.status)
	}
	if q.since == nil || q.until == nil || *q.since > *q.until {
		t.Fatalf("day bounds since=%v until=%v", q.since, q.until)
	}
	// date-only until covers the whole UTC day
	if *q.until-*q.since != int64(24*time.Hour/time.Millisecond)-1 {
		t.Fatalf("day span = %d", *q.until-*q.since)
	}
	if _, _, _, _, err := parsePaymentListArgs(map[string]any{"direction": "sideways"}); err == nil {
		t.Fatal("expected direction error")
	}
	if _, _, _, _, err := parsePaymentListArgs(map[string]any{"until": "2020-01-01", "since": "2021-01-01"}); err == nil {
		t.Fatal("expected until-before-since error")
	}
	if _, _, _, _, err := parsePaymentListArgs(map[string]any{"start_index": "0001-ln_abc"}); err == nil {
		t.Fatal("expected start_index error")
	}
}

func TestListPaymentsRequiresIdentity(t *testing.T) {
	old := cfg
	cfg = config{}
	t.Cleanup(func() { cfg = old })
	_, err := callLexeTool("lexe.list_payments", map[string]any{"summary": true}, "")
	if err == nil || !strings.Contains(err.Error(), "missing Lexe identity") {
		t.Fatalf("got %v", err)
	}
}

func TestListPaymentsToolAdvertised(t *testing.T) {
	var names []string
	for _, tool := range buildTools() {
		names = append(names, asString(tool["name"]))
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"lexe.create_invoice", "lexe.pay", "lexe.analyze", "lexe.check_payment", "lexe.node_health", "lexe.list_payments"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %s", want, joined)
		}
	}
}
