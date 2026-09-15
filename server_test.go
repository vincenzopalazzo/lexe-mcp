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
