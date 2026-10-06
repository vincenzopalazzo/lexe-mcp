// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParseBIP353HRN(t *testing.T) {
	cases := []struct {
		in       string
		user     string
		domain   string
		explicit bool
		ok       bool
	}{
		{"alice@example.com", "alice", "example.com", false, true},
		{"₿alice@example.com", "alice", "example.com", true, true},
		{"bitcoin:alice@example.com", "alice", "example.com", true, true},
		{"bitcoin:₿alice@example.com", "alice", "example.com", true, true},
		{"send.some@satsto.me", "send.some", "satsto.me", false, true},
		{"alice@example.com.", "alice", "example.com", false, true},
		{"bitcoin:?lno=lno1abc", "", "", false, false},
		{"lnurl1dp68gurn8ghj7", "", "", false, false},
		{"lnbc10u1pabc", "", "", false, false},
		{"not a name", "", "", false, false},
	}
	for _, c := range cases {
		hrn, explicit, ok := parseBIP353HRN(c.in)
		if ok != c.ok || explicit != c.explicit || hrn.User != c.user || hrn.Domain != c.domain {
			t.Errorf("parseBIP353HRN(%q) = (%q, %q, explicit=%v, ok=%v), want (%q, %q, explicit=%v, ok=%v)",
				c.in, hrn.User, hrn.Domain, explicit, ok, c.user, c.domain, c.explicit, c.ok)
		}
	}
	hrn, _, ok := parseBIP353HRN("alice@example.com")
	if !ok || hrn.dnsName() != "alice.user._bitcoin-payment.example.com." {
		t.Fatalf("dns name %q", hrn.dnsName())
	}
}

func TestAnalyzeBitcoinURI(t *testing.T) {
	m, ok, err := analyzeBitcoinURI("bitcoin:?lno=lno1qxyz&amount=0.00000021")
	if err != nil || !ok {
		t.Fatalf("uri: ok=%v err=%v", ok, err)
	}
	picked, err := pickLightningPayable(m)
	if err != nil {
		t.Fatal(err)
	}
	if asString(picked["kind"]) != "offer" || asString(picked["offer"]) != "lno1qxyz" {
		t.Fatalf("picked %#v", picked)
	}
	amt, has := satsInt(picked["amount"])
	if !has || amt != 21 {
		t.Fatalf("amount %#v", picked["amount"])
	}

	m, ok, err = analyzeBitcoinURI("bitcoin:?lightning=lnbc10u1pabc&lno=lno1qxyz")
	if err != nil || !ok {
		t.Fatal(err)
	}
	picked, err = pickLightningPayable(m)
	if err != nil || asString(picked["kind"]) != "offer" {
		t.Fatalf("offer should win over bolt11, picked %#v err %v", picked, err)
	}

	m, ok, err = analyzeBitcoinURI("bitcoin:bc1qexampleaddress")
	if err != nil || !ok {
		t.Fatalf("on-chain uri ok=%v err=%v", ok, err)
	}
	if _, err := pickLightningPayable(m); err == nil {
		t.Fatal("expected on-chain refusal")
	}

	if _, _, err := analyzeBitcoinURI("bitcoin:?lno=lno1qxyz&amount=0.000000001"); err == nil {
		t.Fatal("expected sub-sat rejection")
	}
}

func TestRootTrustAnchorKeyTag(t *testing.T) {
	pub, err := base64.StdEncoding.DecodeString("AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=")
	if err != nil {
		t.Fatal(err)
	}
	key := dnsRR{name: ".", typ: dnsTypeDNSKEY, flags: 257, protocol: 3, alg: 8, pubkey: pub}
	if key.tag() != 20326 {
		t.Fatalf("key tag %d", key.tag())
	}
	sum, err := dsDigest(key, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmtHex(sum); got != "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d" {
		t.Fatalf("ds digest %s", got)
	}
}

func fmtHex(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexd[c>>4]
		out[i*2+1] = hexd[c&0x0f]
	}
	return string(out)
}

func TestNSECOrderRFC4034(t *testing.T) {
	names := []string{
		"example.",
		"a.example.",
		"yljkjljk.a.example.",
		"Z.a.example.",
		"zABC.a.EXAMPLE.",
		"z.example.",
		"\x01.z.example.",
		"*.z.example.",
		"\xc8.z.example.",
	}
	for i := 1; i < len(names); i++ {
		if nsecOrd([]byte(names[i-1]), []byte(names[i])) >= 0 {
			t.Fatalf("%q should sort before %q", names[i-1], names[i])
		}
	}
}

func TestBitcoinTXTRules(t *testing.T) {
	one := []dnsRR{{
		name: "a.example.",
		typ:  dnsTypeTXT,
		txt:  [][]byte{[]byte("bitcoin:?ln"), []byte("o=lno1abc")},
	}, {
		name: "a.example.",
		typ:  dnsTypeTXT,
		txt:  [][]byte{[]byte("not bitcoin")},
	}}
	uri, err := bitcoinTXT(one)
	if err != nil || uri != "bitcoin:?lno=lno1abc" {
		t.Fatalf("uri %q err %v", uri, err)
	}
	two := append(one, dnsRR{typ: dnsTypeTXT, txt: [][]byte{[]byte("BITCOIN:?lno=lno1other")}})
	if _, err := bitcoinTXT(two); err == nil || !strings.Contains(err.Error(), "Multiple TXT") {
		t.Fatalf("err %v", err)
	}
}

func p256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func p256DNSKEY(name string, flags uint16, k *ecdsa.PrivateKey) dnsRR {
	pub := make([]byte, 64)
	k.X.FillBytes(pub[:32])
	k.Y.FillBytes(pub[32:])
	return dnsRR{name: name, typ: dnsTypeDNSKEY, flags: flags, protocol: 3, alg: 13, pubkey: pub, ttl: 3600}
}

func signSet(t *testing.T, priv *ecdsa.PrivateKey, owner, signer string, typ uint16, keyTag uint16, recs []dnsRR) dnsRR {
	t.Helper()
	now := uint32(time.Now().Unix())
	sig := dnsRR{
		name: owner, typ: dnsTypeRRSIG, ttl: 3600,
		sigType: typ, alg: 13, sigLabels: byte(nameLabels(owner)),
		origTTL: 3600, expiration: now + 86400, inception: now - 3600,
		keyTag: keyTag, signer: signer,
	}
	digest, err := rrsetDigest(sig, recs)
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	sig.signature = append(padInt(r, 32), padInt(s, 32)...)
	return sig
}

func padInt(n *big.Int, size int) []byte {
	out := make([]byte, size)
	n.FillBytes(out)
	return out
}

func wireAll(t *testing.T, rrs []dnsRR) []byte {
	t.Helper()
	var buf []byte
	var err error
	for _, rr := range rrs {
		buf, err = appendRRWire(buf, rr)
		if err != nil {
			t.Fatal(err)
		}
	}
	return buf
}

func TestSyntheticBIP353Proof(t *testing.T) {
	saved := append([]dnsRR(nil), rootDS...)
	t.Cleanup(func() { rootDS = saved })

	rootKSK := p256Key(t)
	rootZSK := p256Key(t)
	exKSK := p256Key(t)
	exZSK := p256Key(t)

	rootKeys := []dnsRR{
		p256DNSKEY(".", 257, rootKSK),
		p256DNSKEY(".", 256, rootZSK),
	}
	rootKeySig := signSet(t, rootKSK, ".", ".", dnsTypeDNSKEY, rootKeys[0].tag(), rootKeys)
	rootDS = []dnsRR{{
		name: ".", typ: dnsTypeDS, keyTag: rootKeys[0].tag(), alg: 13, digestType: 2,
	}}
	sum, err := dsDigest(rootKeys[0], 2)
	if err != nil {
		t.Fatal(err)
	}
	rootDS[0].digest = sum

	exDS := dnsRR{name: "example.com.", typ: dnsTypeDS, alg: 13, digestType: 2, ttl: 3600}
	exKSKRR := p256DNSKEY("example.com.", 257, exKSK)
	exDS.keyTag = exKSKRR.tag()
	dsum, err := dsDigest(exKSKRR, 2)
	if err != nil {
		t.Fatal(err)
	}
	exDS.digest = dsum
	exDSSig := signSet(t, rootZSK, "example.com.", ".", dnsTypeDS, rootKeys[1].tag(), []dnsRR{exDS})

	exKeys := []dnsRR{exKSKRR, p256DNSKEY("example.com.", 256, exZSK)}
	exKeySig := signSet(t, exKSK, "example.com.", "example.com.", dnsTypeDNSKEY, exKeys[0].tag(), exKeys)

	qname := "alice.user._bitcoin-payment.example.com."
	txt := dnsRR{
		name: qname, typ: dnsTypeTXT, ttl: 300,
		txt: [][]byte{[]byte("bitcoin:?ln"), []byte("o=lno1qxyz")},
	}
	// A second TXT that does not start with bitcoin: must be ignored.
	note := dnsRR{name: qname, typ: dnsTypeTXT, ttl: 300, txt: [][]byte{[]byte("hello")}}
	txtSig := signSet(t, exZSK, qname, "example.com.", dnsTypeTXT, exKeys[1].tag(), []dnsRR{txt, note})

	proof := wireAll(t, []dnsRR{
		txt, note, txtSig,
		exDS, exDSSig,
		exKeys[0], exKeys[1], exKeySig,
		rootKeys[0], rootKeys[1], rootKeySig,
	})
	uri, err := authenticatedBitcoinURI(proof, qname, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if uri != "bitcoin:?lno=lno1qxyz" {
		t.Fatalf("uri %q", uri)
	}

	proof[len(proof)-1] ^= 0xff
	if _, err := authenticatedBitcoinURI(proof, qname, time.Now()); err == nil {
		t.Fatal("tampered proof was accepted")
	}
}

func TestProofBuilderResolvesSyntheticZone(t *testing.T) {
	savedRoot := append([]dnsRR(nil), rootDS...)
	savedDoH := dohExchange
	t.Cleanup(func() {
		rootDS = savedRoot
		dohExchange = savedDoH
	})

	rootKSK := p256Key(t)
	rootZSK := p256Key(t)
	exKSK := p256Key(t)
	exZSK := p256Key(t)
	rootKeys := []dnsRR{p256DNSKEY(".", 257, rootKSK), p256DNSKEY(".", 256, rootZSK)}
	rootKeySig := signSet(t, rootKSK, ".", ".", dnsTypeDNSKEY, rootKeys[0].tag(), rootKeys)
	sum, err := dsDigest(rootKeys[0], 2)
	if err != nil {
		t.Fatal(err)
	}
	rootDS = []dnsRR{{name: ".", typ: dnsTypeDS, keyTag: rootKeys[0].tag(), alg: 13, digestType: 2, digest: sum}}

	exKSKRR := p256DNSKEY("example.com.", 257, exKSK)
	exZSKRR := p256DNSKEY("example.com.", 256, exZSK)
	exKeys := []dnsRR{exKSKRR, exZSKRR}
	exKeySig := signSet(t, exKSK, "example.com.", "example.com.", dnsTypeDNSKEY, exKSKRR.tag(), exKeys)
	dsum, err := dsDigest(exKSKRR, 2)
	if err != nil {
		t.Fatal(err)
	}
	exDS := dnsRR{name: "example.com.", typ: dnsTypeDS, keyTag: exKSKRR.tag(), alg: 13, digestType: 2, digest: dsum, ttl: 600}
	exDSSig := signSet(t, rootZSK, "example.com.", ".", dnsTypeDS, rootKeys[1].tag(), []dnsRR{exDS})

	qname := "alice.user._bitcoin-payment.example.com."
	txt := dnsRR{name: qname, typ: dnsTypeTXT, ttl: 120, txt: [][]byte{[]byte("bitcoin:?lno=lno1qxyz")}}
	txtSig := signSet(t, exZSK, qname, "example.com.", dnsTypeTXT, exZSKRR.tag(), []dnsRR{txt})

	zone := map[string][]dnsRR{
		qname:          {txt, txtSig},
		"example.com.": {exKeys[0], exKeys[1], exKeySig, exDS, exDSSig},
		".":            {rootKeys[0], rootKeys[1], rootKeySig},
	}
	// DS lives at example.com, DNSKEY too. A DS query and a DNSKEY query
	// both ask for example.com but different types. Split by type.
	byType := map[string]map[uint16][]dnsRR{
		qname: {
			dnsTypeTXT: {txt, txtSig},
		},
		"example.com.": {
			dnsTypeDNSKEY: {exKeys[0], exKeys[1], exKeySig},
			dnsTypeDS:     {exDS, exDSSig},
		},
		".": {
			dnsTypeDNSKEY: {rootKeys[0], rootKeys[1], rootKeySig},
		},
	}
	_ = zone
	dohExchange = func(ctx context.Context, query []byte) ([]byte, error) {
		name, typ, err := parseDNSQuery(query)
		if err != nil {
			return nil, err
		}
		rrs := byType[name][typ]
		if len(rrs) == 0 {
			return dnsNoData(query), nil
		}
		return dnsAnswers(query, rrs), nil
	}

	uri, err := resolveBIP353(context.Background(), bip353HRN{User: "alice", Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if uri != "bitcoin:?lno=lno1qxyz" {
		t.Fatalf("uri %q", uri)
	}

	m, err := analyzePaymentString(uri, "")
	if err != nil {
		t.Fatal(err)
	}
	picked, err := pickLightningPayable(m)
	if err != nil || asString(picked["offer"]) != "lno1qxyz" {
		t.Fatalf("picked %#v err %v", picked, err)
	}
}

func dnsAnswers(query []byte, answers []dnsRR) []byte {
	name, typ, err := parseDNSQuery(query)
	if err != nil {
		return nil
	}
	// QR | RD | RA | AD
	hdr := []byte{0, 0, 0x81, 0xa0}
	hdr = append(hdr, 0, 1) // questions
	hdr = appendU16(hdr, uint16(len(answers)))
	hdr = append(hdr, 0, 0, 0, 0) // authority, additional
	hdr = appendName(hdr, name)
	hdr = appendU16(hdr, typ)
	hdr = appendU16(hdr, 1)
	for _, rr := range answers {
		hdr, err = appendRRWire(hdr, rr)
		if err != nil {
			return nil
		}
	}
	return hdr
}

func dnsNoData(query []byte) []byte {
	name, typ, err := parseDNSQuery(query)
	if err != nil {
		return nil
	}
	hdr := []byte{0, 0, 0x81, 0xa0, 0, 1, 0, 0, 0, 0, 0, 0}
	hdr = appendName(hdr, name)
	hdr = appendU16(hdr, typ)
	hdr = appendU16(hdr, 1)
	return hdr
}

func TestWildcardNSEC3Proof(t *testing.T) {
	saved := append([]dnsRR(nil), rootDS...)
	t.Cleanup(func() { rootDS = saved })

	rootKSK := p256Key(t)
	rootZSK := p256Key(t)
	exKSK := p256Key(t)
	exZSK := p256Key(t)
	rootKeys := []dnsRR{p256DNSKEY(".", 257, rootKSK), p256DNSKEY(".", 256, rootZSK)}
	rootKeySig := signSet(t, rootKSK, ".", ".", dnsTypeDNSKEY, rootKeys[0].tag(), rootKeys)
	sum, err := dsDigest(rootKeys[0], 2)
	if err != nil {
		t.Fatal(err)
	}
	rootDS = []dnsRR{{name: ".", typ: dnsTypeDS, keyTag: rootKeys[0].tag(), alg: 13, digestType: 2, digest: sum}}

	exKSKRR := p256DNSKEY("example.com.", 257, exKSK)
	exZSKRR := p256DNSKEY("example.com.", 256, exZSK)
	exKeys := []dnsRR{exKSKRR, exZSKRR}
	exKeySig := signSet(t, exKSK, "example.com.", "example.com.", dnsTypeDNSKEY, exKSKRR.tag(), exKeys)
	dsum, err := dsDigest(exKSKRR, 2)
	if err != nil {
		t.Fatal(err)
	}
	exDS := dnsRR{name: "example.com.", typ: dnsTypeDS, keyTag: exKSKRR.tag(), alg: 13, digestType: 2, digest: dsum, ttl: 600}
	exDSSig := signSet(t, rootZSK, "example.com.", ".", dnsTypeDS, rootKeys[1].tag(), []dnsRR{exDS})

	qname := "alice.user._bitcoin-payment.example.com."
	txt := dnsRR{name: qname, typ: dnsTypeTXT, ttl: 120, txt: [][]byte{[]byte("bitcoin:?lno=lno1qwild")}}
	// Signed as *.user._bitcoin-payment.example.com (4 labels; the star is not counted).
	txtSig := signSet(t, exZSK, qname, "example.com.", dnsTypeTXT, exZSKRR.tag(), []dnsRR{txt})
	txtSig.sigLabels = byte(nameLabels(qname) - 1)
	txtSig.signature = nil
	digest, err := rrsetDigest(txtSig, []dnsRR{txt})
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, exZSK, digest)
	if err != nil {
		t.Fatal(err)
	}
	txtSig.signature = append(padInt(r, 32), padInt(s, 32)...)

	var start, next [20]byte
	for i := range next {
		next[i] = 0xff
	}
	owner := strings.ToLower(nsec3Base32.EncodeToString(start[:])) + ".example.com."
	nsec := dnsRR{
		name: owner, typ: dnsTypeNSEC3, ttl: 120,
		nsec3Algo: 1, nsec3Flags: 0, nsec3Iter: 0,
		nsec3Next: next[:],
	}
	nsecSig := signSet(t, exZSK, owner, "example.com.", dnsTypeNSEC3, exZSKRR.tag(), []dnsRR{nsec})
	proof := wireAll(t, []dnsRR{
		txt, txtSig, nsec, nsecSig,
		exDS, exDSSig, exKeys[0], exKeys[1], exKeySig,
		rootKeys[0], rootKeys[1], rootKeySig,
	})
	uri, err := authenticatedBitcoinURI(proof, qname, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if uri != "bitcoin:?lno=lno1qwild" {
		t.Fatalf("uri %q", uri)
	}

	// The covered span is exclusive of the end hash, so ending exactly on the
	// name hash does not prove the name is absent.
	nsec.nsec3Next = nsec3Hash(qname, nil, 0)
	nsecSig = signSet(t, exZSK, owner, "example.com.", dnsTypeNSEC3, exZSKRR.tag(), []dnsRR{nsec})
	gap := wireAll(t, []dnsRR{
		txt, txtSig, nsec, nsecSig,
		exDS, exDSSig, exKeys[0], exKeys[1], exKeySig,
		rootKeys[0], rootKeys[1], rootKeySig,
	})
	if _, err := authenticatedBitcoinURI(gap, qname, time.Now()); err == nil {
		t.Fatal("wildcard without a covering NSEC3 was accepted")
	}
}

func TestLiveBIP353(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	uri, err := resolveBIP353(ctx, bip353HRN{User: "send.some", Domain: "satsto.me"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.ToLower(uri), "bitcoin:") {
		t.Fatalf("uri %q", uri)
	}
	m, err := analyzePaymentString(uri, "")
	if err != nil {
		t.Fatal(err)
	}
	picked, err := pickLightningPayable(m)
	if err != nil {
		t.Fatalf("no lightning payable in %q: %v", uri, err)
	}
	if asString(picked["kind"]) != "offer" && asString(picked["kind"]) != "invoice" {
		t.Fatalf("picked %#v", picked)
	}
}
