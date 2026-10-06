// SPDX-License-Identifier: Apache-2.0
//
// BIP 353 human-readable payment names (₿user@domain).
//
// Resolution follows bitcoin-payment-instructions' HTTPHrnResolver:
// DNS-over-HTTPS to dns.google, proof assembly via the same query walk
// as dnssec-prover::ProofBuilder, then local DNSSEC validation. LN-Address
// / LNURL is not a fallback — that path stays refused.

package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	bip353ExtraLen = len(".user._bitcoin-payment.") + 1
	dohEndpoint    = "https://dns.google/dns-query?dns="
)

var dohClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// dohExchange is replaced in tests. Production always talks to dns.google.
var dohExchange = defaultDoHExchange

type bip353HRN struct {
	User   string
	Domain string
}

func (h bip353HRN) dnsName() string {
	return strings.ToLower(h.User) + ".user._bitcoin-payment." + strings.ToLower(h.Domain) + "."
}

func (h bip353HRN) display() string {
	return "₿" + h.User + "@" + h.Domain
}

// parseBIP353HRN accepts user@domain, ₿user@domain, and bitcoin:user@domain.
// explicit is set when the ₿ or bitcoin: prefix was present. A bitcoin: URI
// with a query (the resolved payment instructions) is not an HRN.
func parseBIP353HRN(s string) (bip353HRN, bool, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return bip353HRN{}, false, false
	}
	explicit := false
	if strings.HasPrefix(strings.ToLower(s), "bitcoin:") {
		rest := s[len("bitcoin:"):]
		if strings.ContainsAny(rest, "?/") {
			return bip353HRN{}, false, false
		}
		s = rest
		explicit = true
	}
	if strings.HasPrefix(s, "₿") {
		s = strings.TrimPrefix(s, "₿")
		explicit = true
	}
	user, domain, ok := strings.Cut(s, "@")
	domain = strings.TrimSuffix(domain, ".")
	if !ok || !validHRNPart(user) || !validHRNPart(domain) {
		return bip353HRN{}, false, false
	}
	if len(user)+len(domain)+bip353ExtraLen > 255 {
		return bip353HRN{}, false, false
	}
	return bip353HRN{User: user, Domain: domain}, explicit, true
}

func validHRNPart(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func defaultDoHExchange(ctx context.Context, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dohEndpoint+b64url(query), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", serverName+"/"+serverVersion)
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK || len(body) == 0 || len(body) > 128*1024 {
		return nil, proofError{"DNS Request to dns.google failed"}
	}
	return body, nil
}

func b64url(b []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := make([]byte, 0, (len(b)*8+5)/6)
	for len(b) >= 3 {
		a, c, d := int(b[0]), int(b[1]), int(b[2])
		out = append(out,
			enc[(a&0b11111100)>>2],
			enc[((a&0b00000011)<<4)|((c&0b11110000)>>4)],
			enc[((c&0b00001111)<<2)|((d&0b11000000)>>6)],
			enc[d&0b00111111],
		)
		b = b[3:]
	}
	switch len(b) {
	case 2:
		a, c := int(b[0]), int(b[1])
		out = append(out,
			enc[(a&0b11111100)>>2],
			enc[((a&0b00000011)<<4)|((c&0b11110000)>>4)],
			enc[(c&0b00001111)<<2],
		)
	case 1:
		a := int(b[0])
		out = append(out, enc[(a&0b11111100)>>2], enc[(a&0b00000011)<<4])
	}
	return string(out)
}

func buildTXTProof(ctx context.Context, qname string) ([]byte, error) {
	b := newProofBuilder()
	pending := [][]byte{buildDNSQuery(qname, dnsTypeTXT)}
	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, proofError{"DNS Request to dns.google failed"}
		}
		q := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		resp, err := dohExchange(ctx, q)
		if err != nil {
			return nil, proofError{"DNS Request to dns.google failed"}
		}
		more, err := b.process(resp)
		if err != nil {
			return nil, err
		}
		pending = append(pending, more...)
	}
	return b.finish()
}

// resolveBIP353 returns the validated bitcoin: URI for an HRN.
func resolveBIP353(ctx context.Context, hrn bip353HRN) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	qname := hrn.dnsName()
	proof, err := buildTXTProof(ctx, qname)
	if err != nil {
		return "", httpError{"BIP 353: " + err.Error()}
	}
	uri, err := authenticatedBitcoinURI(proof, qname, time.Now())
	if err != nil {
		return "", httpError{"BIP 353: " + err.Error()}
	}
	return uri, nil
}

func attachBIP353(out, meta map[string]any) {
	if out == nil || meta == nil {
		return
	}
	if e := asString(meta["bip353_error"]); e != "" {
		out["bip353_error"] = e
		return
	}
	out["bip353"] = meta
}

// expandBIP353 resolves an HRN when one is present.
// A plain user@domain that does not resolve stays unchanged and sets
// bip353_error so pay can explain the refusal. An explicit ₿ / bitcoin:
// name that does not resolve is an error.
func expandBIP353(ctx context.Context, s string) (string, map[string]any, error) {
	hrn, explicit, ok := parseBIP353HRN(s)
	if !ok {
		return s, nil, nil
	}
	uri, err := resolveBIP353(ctx, hrn)
	if err != nil {
		if explicit {
			return "", nil, err
		}
		return s, map[string]any{"bip353_error": err.Error()}, nil
	}
	return uri, map[string]any{
		"name":     hrn.display(),
		"dns_name": hrn.dnsName(),
		"uri":      uri,
	}, nil
}

// analyzeBitcoinURI decodes a BIP 21 / BIP 321 bitcoin: URI into Lightning
// payables. lno (BOLT12) is preferred over lightning (BOLT11). On-chain-only
// URIs produce an empty payable list so the existing refusal applies.
func analyzeBitcoinURI(s string) (map[string]any, bool, error) {
	s = strings.TrimSpace(s)
	if len(s) < len("bitcoin:") || !strings.EqualFold(s[:len("bitcoin:")], "bitcoin:") {
		return nil, false, nil
	}
	if _, _, ok := parseBIP353HRN(s); ok {
		return nil, false, nil
	}
	u, err := url.Parse(s)
	if err != nil || !strings.EqualFold(u.Scheme, "bitcoin") {
		return nil, false, nil
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, false, httpError{"invalid bitcoin: URI"}
	}
	var uriAmt int
	hasURIAmt := false
	if raw := strings.TrimSpace(q.Get("amount")); raw != "" {
		uriAmt, hasURIAmt = btcDecimalToSats(raw)
		if !hasURIAmt {
			return nil, true, httpError{"bitcoin: URI amount is not a whole number of sats"}
		}
	}
	var payables []any
	if lno := strings.TrimSpace(q.Get("lno")); lno != "" {
		p, err := payableRecord(lno, uriAmt, hasURIAmt)
		if err != nil {
			return nil, true, err
		}
		if p != nil {
			payables = append(payables, p)
		}
	}
	if invoice := strings.TrimSpace(q.Get("lightning")); invoice != "" {
		p, err := payableRecord(invoice, uriAmt, hasURIAmt)
		if err != nil {
			return nil, true, err
		}
		if p != nil {
			payables = append(payables, p)
		}
	}
	return map[string]any{"payables": payables, "claimables": []any{}}, true, nil
}

func payableRecord(s string, uriAmt int, hasURIAmt bool) (map[string]any, error) {
	raw, kind := classifyPayable(s)
	if kind != "invoice" && kind != "offer" {
		return nil, nil
	}
	p := map[string]any{"kind": kind}
	switch kind {
	case "invoice":
		p["invoice"] = raw
		if sats, ok := bolt11AmountSats(raw); ok {
			if hasURIAmt && uriAmt != sats {
				return nil, httpError{"bitcoin: URI amount does not match the invoice amount"}
			}
			p["amount"] = sats
		} else if hasURIAmt {
			p["amount"] = uriAmt
		}
	case "offer":
		p["offer"] = raw
		if hasURIAmt {
			p["amount"] = uriAmt
		}
	}
	return p, nil
}

func btcDecimalToSats(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "+") {
		return 0, false
	}
	whole, frac, ok := strings.Cut(s, ".")
	if !ok {
		frac = ""
	} else if strings.Contains(frac, ".") {
		return 0, false
	}
	if whole == "" {
		whole = "0"
	}
	if len(frac) > 8 {
		return 0, false
	}
	for len(frac) < 8 {
		frac += "0"
	}
	w, err := strconv.ParseUint(whole, 10, 64)
	if err != nil {
		return 0, false
	}
	f, err := strconv.ParseUint(frac, 10, 64)
	if err != nil {
		return 0, false
	}
	const maxSats = uint64(21000000) * 100000000
	if w > maxSats/100000000 {
		return 0, false
	}
	sats := w*100000000 + f
	if sats > maxSats || sats > uint64(^uint(0)>>1) || sats == 0 {
		return 0, false
	}
	return int(sats), true
}
