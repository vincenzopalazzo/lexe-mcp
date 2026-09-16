// SPDX-License-Identifier: Apache-2.0
package main

import (
	"testing"
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
		{"lnbc10u1pxyz", "invoice"},       // 1000 sats
		{"lntb1qxyz", "invoice"},          // testnet amountless
		{"LNBC1M1XYZ", "invoice"},         // uppercase hrpart
		{"lno1qxyz", "offer"},             // BOLT12
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
		{"lnbc10u1px", 1000, true},    // 10 micro-BTC
		{"lnbc1m1px", 100000, true},   // 1 milli-BTC
		{"lnbc20n1px", 2, true},       // 20 nano-BTC
		{"lnbc1px", 0, false},         // amountless
		{"lnbc1p1px", 0, false},       // pico — sub-sat, treated amountless
		{"lnbc1231px", 12300000000, true}, // 123 BTC
		{"lntb5u1px", 500, true},      // testnet 5 micro
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
