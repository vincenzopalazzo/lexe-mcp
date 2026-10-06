// SPDX-License-Identifier: Apache-2.0
//
// DNSSEC proof construction and validation for BIP 353.
//
// Behavior follows the Rust reference used by Lightning wallets:
//   - dnssec-prover (ProofBuilder + verify_rr_stream), and
//   - bitcoin-payment-instructions (HTTPHrnResolver + resolve_proof).
//
// A recursive resolver is only a transport. Signatures are checked here
// back to the IANA root trust anchors. The AD bit is required to build a
// proof (unsigned zones fail early) and is not treated as authentication.

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"hash"
	"math/big"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	dnsTypeA      uint16 = 1
	dnsTypeNS     uint16 = 2
	dnsTypeCNAME  uint16 = 5
	dnsTypeTXT    uint16 = 16
	dnsTypeDNAME  uint16 = 39
	dnsTypeDS     uint16 = 43
	dnsTypeRRSIG  uint16 = 46
	dnsTypeNSEC   uint16 = 47
	dnsTypeDNSKEY uint16 = 48
	dnsTypeNSEC3  uint16 = 50
	dnsTypeTLSA   uint16 = 52
	dnsTypeAAAA   uint16 = 28

	maxProofSteps = 20
	maxProofBytes = 256 * 1024
	maxRRsInMsg   = 256
)

var (
	errDNSInvalid      = errors.New("invalid")
	errDNSUnsupported  = errors.New("unsupported")
	errDNSTooManySteps = errors.New("too many proof steps")
)

// Root DS records from https://data.iana.org/root-anchors/root-anchors.xml
// (KSK-2017 tag 20326 and KSK-2024 tag 38696). Tests may replace this.
var rootDS = []dnsRR{
	rootDSRecord(20326, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
	rootDSRecord(38696, "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
}

func rootDSRecord(tag uint16, digestHex string) dnsRR {
	return dnsRR{
		name: ".", typ: dnsTypeDS, keyTag: tag, alg: 8, digestType: 2,
		digest: mustUnhex(digestHex),
	}
}

func mustUnhex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		b[i] = unhexNibble(s[i*2])<<4 | unhexNibble(s[i*2+1])
	}
	return b
}

func unhexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		panic("bad hex")
	}
}

// dnsRR is one resource record. Name fields use absolute presentation
// form ("example.com." or ".") and are lowercased, except nsecNext which
// keeps the original octets (RFC 6840 §5.1).
type dnsRR struct {
	name string
	typ  uint16
	ttl  uint32

	txt   [][]byte
	name2 string // CNAME / DNAME / NS target
	addr  []byte // A, AAAA
	raw   []byte // TLSA rdata

	flags    uint16
	protocol byte
	alg      byte
	pubkey   []byte

	keyTag     uint16
	digestType byte
	digest     []byte

	sigType    uint16
	sigLabels  byte
	origTTL    uint32
	expiration uint32
	inception  uint32
	signer     string
	signature  []byte

	nsecNext   []byte
	nsecBits   [8192]byte
	nsec3Algo  byte
	nsec3Flags byte
	nsec3Iter  uint16
	nsec3Salt  []byte
	nsec3Next  []byte
}

func (rr dnsRR) tag() uint16 {
	return dnsKeyTag(rr.flags, rr.protocol, rr.alg, rr.pubkey)
}

func dnsKeyTag(flags uint16, protocol, alg byte, pub []byte) uint16 {
	res := uint32(flags)
	res += uint32(protocol) << 8
	res += uint32(alg)
	for i, b := range pub {
		if i%2 == 0 {
			res += uint32(b) << 8
		} else {
			res += uint32(b)
		}
	}
	res += (res >> 16) & 0xffff
	return uint16(res & 0xffff)
}

func nameLabels(name string) int {
	if name == "." {
		return 0
	}
	n := 0
	for _, c := range name {
		if c == '.' {
			n++
		}
	}
	return n
}

func trailingLabels(name string, n int) (string, bool) {
	labels := nameLabels(name)
	if n > labels {
		return "", false
	}
	if n == labels {
		return name, true
	}
	if n == 0 {
		return ".", true
	}
	parts := strings.SplitN(name, ".", labels-n+1)
	return parts[len(parts)-1], true
}

func endsWithLabels(name []byte, suffix string) bool {
	if len(name) < len(suffix) {
		return false
	}
	if bytes.HasSuffix(name, []byte(".")) && suffix == "." {
		return true
	}
	suf := name[len(name)-len(suffix):]
	if !bytes.EqualFold(suf, []byte(suffix)) {
		return false
	}
	if len(name) == len(suffix) {
		return true
	}
	return name[len(name)-len(suffix)-1] == '.'
}

func endsWithLabelsStr(name, suffix string) bool {
	return endsWithLabels([]byte(name), suffix)
}

func appendName(dst []byte, name string) []byte {
	name = strings.ToLower(name)
	if name == "" || name == "." {
		return append(dst, 0)
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	for _, label := range strings.Split(name, ".") {
		dst = append(dst, byte(len(label)))
		dst = append(dst, label...)
	}
	return dst
}

func appendNameRaw(dst, name []byte) []byte {
	if bytes.Equal(name, []byte(".")) {
		return append(dst, 0)
	}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			dst = append(dst, byte(len(label)))
			dst = append(dst, label...)
			start = i + 1
		}
	}
	return dst
}

func appendU16(dst []byte, v uint16) []byte {
	return append(dst, byte(v>>8), byte(v))
}

func appendU32(dst []byte, v uint32) []byte {
	return append(dst, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func canonicalRData(rr dnsRR) []byte {
	switch rr.typ {
	case dnsTypeA, dnsTypeAAAA:
		return append([]byte(nil), rr.addr...)
	case dnsTypeNS, dnsTypeCNAME, dnsTypeDNAME:
		return appendName(nil, rr.name2)
	case dnsTypeTXT:
		var d []byte
		for _, p := range rr.txt {
			d = append(d, byte(len(p)))
			d = append(d, p...)
		}
		return d
	case dnsTypeTLSA:
		return append([]byte(nil), rr.raw...)
	case dnsTypeDNSKEY:
		d := appendU16(nil, rr.flags)
		d = append(d, rr.protocol, rr.alg)
		return append(d, rr.pubkey...)
	case dnsTypeDS:
		d := appendU16(nil, rr.keyTag)
		d = append(d, rr.alg, rr.digestType)
		return append(d, rr.digest...)
	case dnsTypeRRSIG:
		d := appendU16(nil, rr.sigType)
		d = append(d, rr.alg, rr.sigLabels)
		d = appendU32(d, rr.origTTL)
		d = appendU32(d, rr.expiration)
		d = appendU32(d, rr.inception)
		d = appendU16(d, rr.keyTag)
		d = appendName(d, rr.signer)
		return append(d, rr.signature...)
	case dnsTypeNSEC:
		d := appendNameRaw(nil, rr.nsecNext)
		return appendNSECBitmap(d, rr.nsecBits)
	case dnsTypeNSEC3:
		d := []byte{rr.nsec3Algo, rr.nsec3Flags}
		d = appendU16(d, rr.nsec3Iter)
		d = append(d, byte(len(rr.nsec3Salt)))
		d = append(d, rr.nsec3Salt...)
		d = append(d, byte(len(rr.nsec3Next)))
		d = append(d, rr.nsec3Next...)
		return appendNSECBitmap(d, rr.nsecBits)
	default:
		return nil
	}
}

func appendNSECBitmap(dst []byte, bits [8192]byte) []byte {
	for block := 0; block < 256; block++ {
		w := bits[block*32 : block*32+32]
		last := -1
		for i := 31; i >= 0; i-- {
			if w[i] != 0 {
				last = i
				break
			}
		}
		if last < 0 {
			continue
		}
		dst = append(dst, byte(block), byte(last+1))
		dst = append(dst, w[:last+1]...)
	}
	return dst
}

func readU8(inp *[]byte) (byte, error) {
	b := *inp
	if len(b) < 1 {
		return 0, errDNSInvalid
	}
	*inp = b[1:]
	return b[0], nil
}

func readU16(inp *[]byte) (uint16, error) {
	b := *inp
	if len(b) < 2 {
		return 0, errDNSInvalid
	}
	*inp = b[2:]
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

func readU32(inp *[]byte) (uint32, error) {
	b := *inp
	if len(b) < 4 {
		return 0, errDNSInvalid
	}
	*inp = b[4:]
	return binary.BigEndian.Uint32(b[:4]), nil
}

func readNSECBitmap(data []byte) ([8192]byte, error) {
	var res [8192]byte
	for len(data) > 0 {
		if len(data) < 2 {
			return res, errDNSInvalid
		}
		block := int(data[0])
		n := int(data[1])
		data = data[2:]
		if n == 0 || n > 32 || len(data) < n {
			return res, errDNSInvalid
		}
		copy(res[block*32:block*32+n], data[:n])
		data = data[n:]
	}
	return res, nil
}

func readNameRaw(pkt []byte, inp *[]byte) ([]byte, error) {
	var name []byte
	if err := readLabels(pkt, inp, &name, 255); err != nil {
		return nil, err
	}
	if len(name) > 255 {
		return nil, errDNSInvalid
	}
	return name, nil
}

func readLabels(pkt []byte, inp *[]byte, name *[]byte, limit int) error {
	if limit <= 0 {
		return errDNSInvalid
	}
	b := *inp
	for {
		if len(b) < 1 {
			return errDNSInvalid
		}
		ln := int(b[0])
		b = b[1:]
		if ln == 0 {
			if len(*name) == 0 {
				*name = append(*name, '.')
			}
			*inp = b
			return nil
		}
		if ln >= 0xc0 {
			if len(b) < 1 {
				return errDNSInvalid
			}
			off := ((ln &^ 0xc0) << 8) | int(b[0])
			b = b[1:]
			*inp = b
			if off >= len(pkt) {
				return errDNSInvalid
			}
			rest := pkt[off:]
			return readLabels(pkt, &rest, name, limit-1)
		}
		if ln > 63 || len(b) <= ln {
			return errDNSInvalid
		}
		*name = append(*name, b[:ln]...)
		*name = append(*name, '.')
		b = b[ln:]
		if len(*name) > 255 {
			return errDNSInvalid
		}
	}
}

func presentationName(raw []byte) (string, error) {
	for _, c := range raw {
		if c != '.' && c != '-' && c != '_' && c != '*' &&
			(c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return "", errDNSInvalid
		}
	}
	s := strings.ToLower(string(raw))
	if s == "" || !strings.HasSuffix(s, ".") {
		return "", errDNSInvalid
	}
	return s, nil
}

func readPresentationName(pkt []byte, inp *[]byte) (string, error) {
	raw, err := readNameRaw(pkt, inp)
	if err != nil {
		return "", err
	}
	return presentationName(raw)
}

func parseRData(typ uint16, name string, data []byte, pkt []byte) (dnsRR, error) {
	rr := dnsRR{name: name, typ: typ}
	in := data
	switch typ {
	case dnsTypeA:
		if len(in) != 4 {
			return rr, errDNSInvalid
		}
		rr.addr = append([]byte(nil), in...)
	case dnsTypeAAAA:
		if len(in) != 16 {
			return rr, errDNSInvalid
		}
		rr.addr = append([]byte(nil), in...)
	case dnsTypeNS, dnsTypeCNAME, dnsTypeDNAME:
		target, err := readPresentationName(pkt, &in)
		if err != nil || len(in) != 0 {
			return rr, errDNSInvalid
		}
		rr.name2 = target
	case dnsTypeTXT:
		for len(in) > 0 {
			n, err := readU8(&in)
			if err != nil || n == 0 || len(in) < int(n) {
				return rr, errDNSInvalid
			}
			rr.txt = append(rr.txt, append([]byte(nil), in[:n]...))
			in = in[n:]
		}
	case dnsTypeTLSA:
		if len(in) < 3 {
			return rr, errDNSInvalid
		}
		rr.raw = append([]byte(nil), in...)
	case dnsTypeDNSKEY:
		flags, err := readU16(&in)
		if err != nil {
			return rr, err
		}
		proto, err := readU8(&in)
		if err != nil {
			return rr, err
		}
		alg, err := readU8(&in)
		if err != nil {
			return rr, err
		}
		rr.flags, rr.protocol, rr.alg, rr.pubkey = flags, proto, alg, append([]byte(nil), in...)
	case dnsTypeDS:
		tag, err := readU16(&in)
		if err != nil {
			return rr, err
		}
		alg, err := readU8(&in)
		if err != nil {
			return rr, err
		}
		dt, err := readU8(&in)
		if err != nil {
			return rr, err
		}
		rr.keyTag, rr.alg, rr.digestType, rr.digest = tag, alg, dt, append([]byte(nil), in...)
	case dnsTypeRRSIG:
		st, err := readU16(&in)
		if err != nil {
			return rr, err
		}
		alg, err := readU8(&in)
		if err != nil {
			return rr, err
		}
		labels, err := readU8(&in)
		if err != nil {
			return rr, err
		}
		ttl, err := readU32(&in)
		if err != nil {
			return rr, err
		}
		exp, err := readU32(&in)
		if err != nil {
			return rr, err
		}
		inc, err := readU32(&in)
		if err != nil {
			return rr, err
		}
		tag, err := readU16(&in)
		if err != nil {
			return rr, err
		}
		signer, err := readPresentationName(pkt, &in)
		if err != nil {
			return rr, err
		}
		rr.sigType, rr.alg, rr.sigLabels = st, alg, labels
		rr.origTTL, rr.expiration, rr.inception = ttl, exp, inc
		rr.keyTag, rr.signer = tag, signer
		rr.signature = append([]byte(nil), in...)
	case dnsTypeNSEC:
		next, err := readNameRaw(pkt, &in)
		if err != nil {
			return rr, err
		}
		bits, err := readNSECBitmap(in)
		if err != nil {
			return rr, err
		}
		rr.nsecNext, rr.nsecBits = next, bits
	case dnsTypeNSEC3:
		algo, err := readU8(&in)
		if err != nil {
			return rr, err
		}
		flags, err := readU8(&in)
		if err != nil {
			return rr, err
		}
		iter, err := readU16(&in)
		if err != nil {
			return rr, err
		}
		salt, err := readLenPrefixed(&in)
		if err != nil {
			return rr, err
		}
		next, err := readLenPrefixed(&in)
		if err != nil {
			return rr, err
		}
		bits, err := readNSECBitmap(in)
		if err != nil {
			return rr, err
		}
		rr.nsec3Algo, rr.nsec3Flags, rr.nsec3Iter = algo, flags, iter
		rr.nsec3Salt, rr.nsec3Next, rr.nsecBits = salt, next, bits
	default:
		return rr, errDNSUnknownType
	}
	return rr, nil
}

var errDNSUnknownType = errors.New("unknown dns type")

func readLenPrefixed(inp *[]byte) ([]byte, error) {
	n, err := readU8(inp)
	if err != nil || len(*inp) < int(n) {
		return nil, errDNSInvalid
	}
	out := append([]byte(nil), (*inp)[:n]...)
	*inp = (*inp)[n:]
	return out, nil
}

func parseRR(inp *[]byte, pkt []byte) (dnsRR, error) {
	name, err := readPresentationName(pkt, inp)
	if err != nil {
		return dnsRR{}, err
	}
	typ, err := readU16(inp)
	if err != nil {
		return dnsRR{}, err
	}
	class, err := readU16(inp)
	if err != nil || class != 1 {
		return dnsRR{}, errDNSInvalid
	}
	ttl, err := readU32(inp)
	if err != nil {
		return dnsRR{}, err
	}
	rdlen, err := readU16(inp)
	if err != nil || len(*inp) < int(rdlen) {
		return dnsRR{}, errDNSInvalid
	}
	rdata := (*inp)[:rdlen]
	*inp = (*inp)[rdlen:]
	rr, err := parseRData(typ, name, rdata, pkt)
	if err != nil {
		return dnsRR{}, err
	}
	rr.ttl = ttl
	return rr, nil
}

func parseProof(proof []byte) ([]dnsRR, error) {
	inp := proof
	var out []dnsRR
	for len(inp) > 0 {
		rr, err := parseRR(&inp, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, rr)
		if len(out) > 512 {
			return nil, errDNSInvalid
		}
	}
	return out, nil
}

func appendRRWire(dst []byte, rr dnsRR) ([]byte, error) {
	rdata := canonicalRData(rr)
	if len(rdata) > 65535 {
		return nil, errDNSInvalid
	}
	dst = appendName(dst, rr.name)
	dst = appendU16(dst, rr.typ)
	dst = appendU16(dst, 1)
	dst = appendU32(dst, rr.ttl)
	dst = appendU16(dst, uint16(len(rdata)))
	dst = append(dst, rdata...)
	if len(dst) > maxProofBytes {
		return nil, errDNSInvalid
	}
	return dst, nil
}

func buildDNSQuery(name string, typ uint16) []byte {
	q := []byte{0, 0, 0x01, 0x20, 0, 1, 0, 0, 0, 0, 0, 1}
	q = appendName(q, name)
	q = appendU16(q, typ)
	q = appendU16(q, 1)
	// Root name, TYPE OPT, UDP size 0, ext-rcode 0, version 0, DO bit, no options.
	// Matches dnssec-prover build_query, including the zero UDP payload size.
	q = append(q, 0, 0, 0x29, 0, 0, 0, 0, 0x80, 0, 0, 0)
	return q
}

func parseDNSQuery(q []byte) (string, uint16, error) {
	if len(q) < 12 {
		return "", 0, errDNSInvalid
	}
	inp := q[12:]
	name, err := readPresentationName(q, &inp)
	if err != nil {
		return "", 0, err
	}
	typ, err := readU16(&inp)
	if err != nil {
		return "", 0, err
	}
	return name, typ, nil
}

type proofError struct{ msg string }

func (e proofError) Error() string { return e.msg }

const (
	dnsMsgInvalid  = "The server provided a response we could not understand"
	dnsMsgServfail = "The server indicated it failed to talk to a required authoritative DNS server"
	dnsMsgNoSuch   = "The server indicated the requested hostname does not exist"
	dnsMsgMissing  = "The server indicated one of the records we needed to build our proof did not exist"
	dnsMsgUnauth   = "The server indicated the records we needed were not DNSSEC-authenticated"
)

type proofBuilder struct {
	proof            []byte
	minTTL           uint32
	dnskeysRequested []string
	pending          int
	queriesMade      int
}

func newProofBuilder() *proofBuilder {
	return &proofBuilder{
		minTTL:      ^uint32(0),
		pending:     1,
		queriesMade: 1,
	}
}

func (b *proofBuilder) process(resp []byte) ([][]byte, error) {
	if b.pending == 0 {
		return nil, proofError{dnsMsgInvalid}
	}
	minTTL, signers, err := handleDNSResponse(resp, &b.proof)
	if err != nil {
		if len(b.proof) == 0 && err.Error() == dnsMsgMissing {
			return nil, proofError{dnsMsgNoSuch}
		}
		return nil, err
	}
	if minTTL < b.minTTL {
		b.minTTL = minTTL
	}
	b.pending--
	sort.Strings(signers)
	signers = dedupStrings(signers)
	var queries [][]byte
	for _, signer := range signers {
		if containsStr(b.dnskeysRequested, signer) {
			continue
		}
		queries = append(queries, buildDNSQuery(signer, dnsTypeDNSKEY))
		b.pending++
		b.queriesMade++
		b.dnskeysRequested = append(b.dnskeysRequested, signer)
		if signer != "." {
			queries = append(queries, buildDNSQuery(signer, dnsTypeDS))
			b.pending++
			b.queriesMade++
		}
	}
	if b.queriesMade > maxProofSteps {
		return nil, nil
	}
	return queries, nil
}

func (b *proofBuilder) finish() ([]byte, error) {
	if b.pending > 0 || b.queriesMade > maxProofSteps {
		return nil, proofError{"Too many queries required to build proof"}
	}
	return b.proof, nil
}

func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func handleDNSResponse(resp []byte, proof *[]byte) (uint32, []string, error) {
	if len(resp) < 12 {
		return 0, nil, proofError{dnsMsgInvalid}
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		return 0, nil, proofError{dnsMsgInvalid}
	}
	rcode := flags & 0x000f
	if rcode == 1 || rcode == 2 {
		return 0, nil, proofError{dnsMsgServfail}
	}
	if rcode == 3 {
		return 0, nil, proofError{dnsMsgMissing}
	}
	if flags&0x7a0f != 0 {
		return 0, nil, proofError{dnsMsgInvalid}
	}
	if flags&0x0020 == 0 {
		return 0, nil, proofError{dnsMsgUnauth}
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0 {
		return 0, nil, proofError{dnsMsgInvalid}
	}
	questions := binary.BigEndian.Uint16(resp[4:6])
	answers := binary.BigEndian.Uint16(resp[6:8])
	authorities := binary.BigEndian.Uint16(resp[8:10])
	if questions != 1 || answers == 0 || int(answers) > maxRRsInMsg || int(authorities) > maxRRsInMsg {
		return 0, nil, proofError{dnsMsgInvalid}
	}
	inp := resp[12:]
	for i := 0; i < int(questions); i++ {
		if _, err := readPresentationName(resp, &inp); err != nil {
			return 0, nil, proofError{dnsMsgInvalid}
		}
		if _, err := readU16(&inp); err != nil {
			return 0, nil, proofError{dnsMsgInvalid}
		}
		if _, err := readU16(&inp); err != nil {
			return 0, nil, proofError{dnsMsgInvalid}
		}
	}
	minTTL := uint32(^uint32(0))
	var signers []string
	take := func(rr dnsRR) error {
		var err error
		*proof, err = appendRRWire(*proof, rr)
		if err != nil {
			return proofError{dnsMsgInvalid}
		}
		if rr.ttl < minTTL {
			minTTL = rr.ttl
		}
		if rr.typ == dnsTypeRRSIG {
			signers = append(signers, rr.signer)
		}
		return nil
	}
	for i := 0; i < int(answers); i++ {
		rr, err := parseRR(&inp, resp)
		if err != nil {
			return 0, nil, proofError{dnsMsgInvalid}
		}
		if err := take(rr); err != nil {
			return 0, nil, err
		}
	}
	for i := 0; i < int(authorities); i++ {
		rr, err := parseRR(&inp, resp)
		if errors.Is(err, errDNSUnknownType) {
			// SOA and other non-proof records often sit beside NSEC RRs.
			// The record was already consumed; it is not part of the proof.
			continue
		}
		if err != nil {
			return 0, nil, proofError{dnsMsgInvalid}
		}
		switch rr.typ {
		case dnsTypeNSEC, dnsTypeNSEC3:
		case dnsTypeRRSIG:
			if rr.sigType != dnsTypeNSEC && rr.sigType != dnsTypeNSEC3 {
				continue
			}
		default:
			continue
		}
		if err := take(rr); err != nil {
			return 0, nil, err
		}
	}
	return minTTL, signers, nil
}

func supportedSigAlg(alg byte) bool {
	switch alg {
	case 8, 10, 13, 14:
		return true
	default:
		return false
	}
}

func rrsetDigest(sig dnsRR, recs []dnsRR) ([]byte, error) {
	var h hash.Hash
	switch sig.alg {
	case 8, 13:
		h = sha256.New()
	case 10:
		h = sha512.New()
	case 14:
		h = sha512.New384()
	default:
		return nil, errDNSUnsupported
	}
	buf := appendU16(nil, sig.sigType)
	buf = append(buf, sig.alg, sig.sigLabels)
	buf = appendU32(buf, sig.origTTL)
	buf = appendU32(buf, sig.expiration)
	buf = appendU32(buf, sig.inception)
	buf = appendU16(buf, sig.keyTag)
	buf = appendName(buf, sig.signer)

	type item struct {
		rr    dnsRR
		rdata []byte
	}
	items := make([]item, 0, len(recs))
	for _, r := range recs {
		if r.typ != sig.sigType {
			return nil, errDNSInvalid
		}
		items = append(items, item{rr: r, rdata: canonicalRData(r)})
	}
	sort.Slice(items, func(i, j int) bool {
		return bytes.Compare(items[i].rdata, items[j].rdata) < 0
	})
	dedup := make([]item, 0, len(items))
	var prev []byte
	first := true
	for _, it := range items {
		if !first && bytes.Equal(it.rdata, prev) {
			continue
		}
		first = false
		prev = it.rdata
		dedup = append(dedup, it)
	}
	for _, it := range dedup {
		labels := nameLabels(it.rr.name)
		if it.rr.typ != dnsTypeNSEC && labels != int(sig.sigLabels) {
			if labels < int(sig.sigLabels) || sig.sigLabels == 255 {
				return nil, errDNSInvalid
			}
			tail, ok := trailingLabels(it.rr.name, int(sig.sigLabels))
			if !ok {
				return nil, errDNSInvalid
			}
			buf = append(buf, 1, '*')
			buf = appendName(buf, tail)
		} else {
			buf = appendName(buf, it.rr.name)
		}
		buf = appendU16(buf, it.rr.typ)
		buf = appendU16(buf, 1)
		buf = appendU32(buf, sig.origTTL)
		buf = appendU16(buf, uint16(len(it.rdata)))
		buf = append(buf, it.rdata...)
	}
	_, _ = h.Write(buf)
	return h.Sum(nil), nil
}

func verifyRRSIG(sig dnsRR, keys, recs []dnsRR) error {
	for _, rec := range recs {
		if rec.typ != sig.sigType {
			return errDNSInvalid
		}
	}
	matched := false
	for _, key := range keys {
		if key.typ != dnsTypeDNSKEY || key.tag() != sig.keyTag {
			continue
		}
		if key.protocol != 3 || key.flags&0x100 == 0 || key.flags&0x80 != 0 || key.alg != sig.alg {
			continue
		}
		matched = true
		if !supportedSigAlg(sig.alg) {
			return errDNSUnsupported
		}
		digest, err := rrsetDigest(sig, recs)
		if err != nil {
			return err
		}
		if err := verifyDNSSECSig(sig.alg, key.pubkey, sig.signature, digest); err != nil {
			return errDNSInvalid
		}
		return nil
	}
	if !matched {
		return errDNSInvalid
	}
	return errDNSInvalid
}

func verifyDNSSECSig(alg byte, pub, sig, digest []byte) error {
	switch alg {
	case 8:
		return verifyRSASHA(pub, sig, digest, crypto.SHA256)
	case 10:
		return verifyRSASHA(pub, sig, digest, crypto.SHA512)
	case 13:
		return verifyECDSA(elliptic.P256(), 32, pub, sig, digest)
	case 14:
		return verifyECDSA(elliptic.P384(), 48, pub, sig, digest)
	default:
		return errDNSUnsupported
	}
}

func verifyRSASHA(pub, sig, digest []byte, h crypto.Hash) error {
	key, err := parseDNSSECRSA(pub)
	if err != nil {
		return err
	}
	if key.N.BitLen() < 1024 {
		return errDNSInvalid
	}
	if err := rsa.VerifyPKCS1v15(key, h, digest, sig); err != nil {
		return errDNSInvalid
	}
	return nil
}

func parseDNSSECRSA(pub []byte) (*rsa.PublicKey, error) {
	if len(pub) <= 3 {
		return nil, errDNSInvalid
	}
	var expLen, pos int
	if pub[0] == 0 {
		expLen = int(pub[1])<<8 | int(pub[2])
		pos = 3
	} else {
		expLen = int(pub[0])
		pos = 1
	}
	if expLen == 0 || expLen > 4 || len(pub) <= pos+expLen {
		return nil, errDNSInvalid
	}
	exp := 0
	for _, b := range pub[pos : pos+expLen] {
		exp = exp<<8 | int(b)
	}
	modBytes := pub[pos+expLen:]
	if len(modBytes) < 128 || len(modBytes) > 512 {
		return nil, errDNSInvalid
	}
	n := new(big.Int).SetBytes(modBytes)
	if n.Sign() <= 0 || n.BitLen() < 1024 {
		return nil, errDNSInvalid
	}
	return &rsa.PublicKey{N: n, E: exp}, nil
}

func verifyECDSA(curve elliptic.Curve, n int, pub, sig, digest []byte) error {
	if len(pub) != 2*n || len(sig) != 2*n {
		return errDNSInvalid
	}
	x := new(big.Int).SetBytes(pub[:n])
	y := new(big.Int).SetBytes(pub[n:])
	r := new(big.Int).SetBytes(sig[:n])
	s := new(big.Int).SetBytes(sig[n:])
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return errDNSInvalid
	}
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}, digest, r, s) {
		return errDNSInvalid
	}
	return nil
}

func dsDigest(key dnsRR, digestType byte) ([]byte, error) {
	var h hash.Hash
	switch digestType {
	case 1:
		h = sha1.New()
	case 2:
		h = sha256.New()
	case 4:
		h = sha512.New384()
	default:
		return nil, errDNSUnsupported
	}
	buf := appendName(nil, key.name)
	buf = appendU16(buf, key.flags)
	buf = append(buf, key.protocol, key.alg)
	buf = append(buf, key.pubkey...)
	_, _ = h.Write(buf)
	return h.Sum(nil), nil
}

func verifyDNSKeys(sigs, dses, keys []dnsRR) (dnsRR, error) {
	if len(dses) == 0 {
		return dnsRR{}, errDNSInvalid
	}
	known := false
	trustSHA1 := true
	for _, ds := range dses {
		if ds.digestType == 2 || ds.digestType == 4 {
			trustSHA1 = false
			known = true
		}
		if ds.digestType == 1 || ds.digestType == 2 || ds.digestType == 4 {
			known = true
		}
	}
	if !known {
		return dnsRR{}, errDNSUnsupported
	}
	var validated []dnsRR
	for _, key := range keys {
		for _, ds := range dses {
			if ds.alg != key.alg || ds.keyTag != key.tag() {
				continue
			}
			if ds.digestType == 1 && !trustSHA1 {
				continue
			}
			if ds.digestType != 1 && ds.digestType != 2 && ds.digestType != 4 {
				continue
			}
			sum, err := dsDigest(key, ds.digestType)
			if err != nil {
				continue
			}
			if bytes.Equal(sum, ds.digest) {
				validated = append(validated, key)
				break
			}
		}
	}
	unsupported := false
	for _, sig := range sigs {
		okTag := false
		for _, key := range validated {
			if key.tag() == sig.keyTag {
				okTag = true
				break
			}
		}
		if !okTag {
			continue
		}
		err := verifyRRSIG(sig, validated, keys)
		switch {
		case err == nil:
			return sig, nil
		case errors.Is(err, errDNSUnsupported):
			unsupported = true
		default:
			return dnsRR{}, errDNSInvalid
		}
	}
	if unsupported {
		return dnsRR{}, errDNSUnsupported
	}
	return dnsRR{}, errDNSInvalid
}

func resolveDNSTime(t uint32) uint64 {
	// dnssec-prover: timestamps before ~1997 are treated as past 2106.
	if t < 60*60*24*365*27 {
		return uint64(t) + uint64(^uint32(0))
	}
	return uint64(t)
}

type verifiedRRs struct {
	rrs       []dnsRR
	validFrom uint64
	expires   uint64
}

func verifyRRStream(inp []dnsRR) (verifiedRRs, error) {
	zone := "."
	var res []dnsRR
	var needs []absenceNeed
	var nsecs []nsecSaved
	var pending []dsPending
	var latestInception uint64
	earliestExpiry := uint64(^uint64(0))
	steps := 0
	processedRoot := false
	for {
		if processedRoot && len(pending) == 0 {
			break
		}
		var dses []dnsRR
		if len(pending) > 0 {
			last := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			zone = last.zone
			dses = last.ds
		} else {
			zone = "."
			processedRoot = true
		}
		steps++
		if steps > maxProofSteps {
			return verifiedRRs{}, errDNSTooManySteps
		}
		var dnskeySigs, dnskeys []dnsRR
		for _, rr := range inp {
			if rr.typ == dnsTypeRRSIG && rr.name == zone && rr.sigType == dnsTypeDNSKEY {
				dnskeySigs = append(dnskeySigs, rr)
			}
			if rr.typ == dnsTypeDNSKEY && rr.name == zone {
				dnskeys = append(dnskeys, rr)
			}
		}
		var verified dnsRR
		var err error
		if zone == "." {
			verified, err = verifyDNSKeys(dnskeySigs, rootDS, dnskeys)
		} else {
			verified, err = verifyDNSKeys(dnskeySigs, dses, dnskeys)
		}
		if err != nil {
			return verifiedRRs{}, err
		}
		if t := resolveDNSTime(verified.inception); t > latestInception {
			latestInception = t
		}
		if t := resolveDNSTime(verified.expiration); t < earliestExpiry {
			earliestExpiry = t
		}
		for _, rr := range inp {
			if rr.typ != dnsTypeRRSIG || rr.signer != zone || rr.sigType == dnsTypeDNSKEY {
				continue
			}
			steps++
			if steps > maxProofSteps {
				return verifiedRRs{}, errDNSTooManySteps
			}
			if !endsWithLabelsStr(rr.name, zone) {
				return verifiedRRs{}, errDNSInvalid
			}
			var signed []dnsRR
			for _, rec := range inp {
				if rec.name == rr.name && rec.typ == rr.sigType {
					signed = append(signed, rec)
				}
			}
			err := verifyRRSIG(rr, dnskeys, signed)
			if errors.Is(err, errDNSUnsupported) {
				continue
			}
			if err != nil {
				return verifiedRRs{}, err
			}
			if t := resolveDNSTime(rr.inception); t > latestInception {
				latestInception = t
			}
			if t := resolveDNSTime(rr.expiration); t < earliestExpiry {
				earliestExpiry = t
			}
			switch rr.sigType {
			case dnsTypeRRSIG, dnsTypeDNSKEY:
				return verifiedRRs{}, errDNSInvalid
			case dnsTypeDS:
				if rr.sigLabels != byte(nameLabels(rr.name)) {
					continue
				}
				if !pendingHas(pending, rr.name) {
					var ds []dnsRR
					for _, rec := range signed {
						if rec.typ == dnsTypeDS {
							ds = append(ds, rec)
						}
					}
					pending = append(pending, dsPending{zone: rr.name, ds: ds})
				}
			default:
				if rr.sigLabels != byte(nameLabels(rr.name)) && rr.sigType != dnsTypeNSEC {
					if rr.sigType == dnsTypeNSEC3 || rr.sigLabels == 255 {
						return verifiedRRs{}, errDNSInvalid
					}
					proofName, ok := trailingLabels(rr.name, int(rr.sigLabels)+1)
					if !ok {
						return verifiedRRs{}, errDNSInvalid
					}
					needs = append(needs, absenceNeed{name: proofName, zone: rr.signer})
				}
				for _, rec := range signed {
					if rrIn(res, rec) {
						continue
					}
					if rec.typ == dnsTypeNSEC || rec.typ == dnsTypeNSEC3 {
						nsecs = append(nsecs, nsecSaved{rr: rec, zone: rr.signer})
					}
					res = append(res, rec)
				}
			}
		}
	}
	if len(res) == 0 || latestInception >= earliestExpiry {
		return verifiedRRs{}, errDNSInvalid
	}
	sort.Slice(needs, func(i, j int) bool {
		return nsecOrd([]byte(needs[i].name), []byte(needs[j].name)) < 0
	})
	for len(needs) > 0 {
		n := needs[len(needs)-1]
		needs = needs[:len(needs)-1]
		if nsecProves(nsecs, n.name, n.zone) {
			needs = dropNeed(needs, n)
			continue
		}
		return verifiedRRs{}, errDNSInvalid
	}
	filtered := res[:0]
	for _, rr := range res {
		if rr.typ == dnsTypeNSEC || rr.typ == dnsTypeNSEC3 {
			continue
		}
		filtered = append(filtered, rr)
	}
	return verifiedRRs{rrs: filtered, validFrom: latestInception, expires: earliestExpiry}, nil
}

type dsPending struct {
	zone string
	ds   []dnsRR
}

func pendingHas(pending []dsPending, zone string) bool {
	for _, p := range pending {
		if p.zone == zone {
			return true
		}
	}
	return false
}

func rrIn(rrs []dnsRR, rr dnsRR) bool {
	rd := canonicalRData(rr)
	for _, have := range rrs {
		if have.name == rr.name && have.typ == rr.typ && bytes.Equal(canonicalRData(have), rd) {
			return true
		}
	}
	return false
}

type absenceNeed struct{ name, zone string }

func dropNeed(needs []absenceNeed, n absenceNeed) []absenceNeed {
	out := needs[:0]
	for _, x := range needs {
		if x.name == n.name && x.zone == n.zone {
			continue
		}
		out = append(out, x)
	}
	return out
}

type nsecSaved struct {
	rr   dnsRR
	zone string
}

func nsecProves(nsecs []nsecSaved, name, zone string) bool {
	for _, n := range nsecs {
		if n.zone != zone || n.rr.typ != dnsTypeNSEC {
			continue
		}
		if endsWithLabels(n.rr.nsecNext, name) {
			continue
		}
		owner := []byte(n.rr.name)
		next := n.rr.nsecNext
		want := []byte(name)
		after := nsecOrd(owner, want) < 0
		before := nsecOrd(next, want) > 0
		contained := after && before
		if nsecOrd(owner, next) >= 0 {
			contained = after || before
		}
		if contained {
			return true
		}
	}
	type param struct {
		iter uint16
		salt string
		hash []byte
	}
	var params []param
	for _, n := range nsecs {
		if n.zone != zone || n.rr.typ != dnsTypeNSEC3 {
			continue
		}
		if n.rr.nsec3Iter > 2500 || n.rr.nsec3Algo != 1 {
			continue
		}
		saltKey := string(n.rr.nsec3Salt)
		seen := false
		for _, p := range params {
			if p.iter == n.rr.nsec3Iter && p.salt == saltKey {
				seen = true
				break
			}
		}
		if seen {
			continue
		}
		params = append(params, param{
			iter: n.rr.nsec3Iter,
			salt: saltKey,
			hash: nsec3Hash(name, n.rr.nsec3Salt, int(n.rr.nsec3Iter)),
		})
		if len(params) >= 2 {
			break
		}
	}
	for _, n := range nsecs {
		if n.zone != zone || n.rr.typ != dnsTypeNSEC3 {
			continue
		}
		if n.rr.nsec3Flags != 0 || n.rr.nsec3Algo != 1 {
			continue
		}
		var nameHash []byte
		for _, p := range params {
			if p.iter == n.rr.nsec3Iter && p.salt == string(n.rr.nsec3Salt) {
				nameHash = p.hash
				break
			}
		}
		if nameHash == nil {
			continue
		}
		label, _, _ := strings.Cut(n.rr.name, ".")
		start, err := nsec3Base32.DecodeString(label)
		if err != nil || len(start) != 20 || len(n.rr.nsec3Next) != 20 {
			continue
		}
		after := bytes.Compare(start, nameHash) < 0
		before := bytes.Compare(n.rr.nsec3Next, nameHash) > 0
		contained := after && before
		if bytes.Compare(start, n.rr.nsec3Next) >= 0 {
			contained = after || before
		}
		if contained {
			return true
		}
	}
	return false
}

var nsec3Base32 = base32.NewEncoding("0123456789ABCDEFGHIJKLMNOPQRSTUV").WithPadding(base32.NoPadding)

func nsec3Hash(name string, salt []byte, iterations int) []byte {
	mac := sha1.New()
	_, _ = mac.Write(appendName(nil, name))
	_, _ = mac.Write(salt)
	sum := mac.Sum(nil)
	for i := 0; i < iterations; i++ {
		mac.Reset()
		_, _ = mac.Write(sum)
		_, _ = mac.Write(salt)
		sum = mac.Sum(nil)
	}
	return sum
}

// nsecOrd is the RFC 4034 canonical name order (rightmost label first).
func nsecOrd(a, b []byte) int {
	ai, bi := len(a), len(b)
	for {
		if ai == 0 && bi == 0 {
			return 0
		}
		if ai == 0 {
			return -1
		}
		if bi == 0 {
			return 1
		}
		aEnd := ai
		for ai > 0 && a[ai-1] != '.' {
			ai--
		}
		aLabel := a[ai:aEnd]
		if ai > 0 && a[ai-1] == '.' {
			ai--
		}
		bEnd := bi
		for bi > 0 && b[bi-1] != '.' {
			bi--
		}
		bLabel := b[bi:bEnd]
		if bi > 0 && b[bi-1] == '.' {
			bi--
		}
		n := len(aLabel)
		if len(bLabel) < n {
			n = len(bLabel)
		}
		for i := 0; i < n; i++ {
			ca, cb := foldASCII(aLabel[i]), foldASCII(bLabel[i])
			if ca < cb {
				return -1
			}
			if ca > cb {
				return 1
			}
		}
		if len(aLabel) != len(bLabel) {
			if len(aLabel) < len(bLabel) {
				return -1
			}
			return 1
		}
	}
}

func foldASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func resolveCNAME(rrs []dnsRR, name string) []dnsRR {
	for step := 0; step < maxProofSteps; step++ {
		redirected := false
		for _, rr := range rrs {
			if rr.name == name && rr.typ == dnsTypeCNAME {
				name = rr.name2
				redirected = true
				break
			}
		}
		if redirected {
			continue
		}
		for _, rr := range rrs {
			if rr.typ != dnsTypeDNAME || len(name) <= len(rr.name) || !endsWithLabelsStr(name, rr.name) {
				continue
			}
			prefix := strings.TrimSuffix(name, rr.name)
			resolved := prefix
			if rr.name2 != "." {
				resolved = prefix + rr.name2
			}
			if resolved == "" || !strings.HasSuffix(resolved, ".") || len(resolved) > 255 {
				return nil
			}
			name = resolved
			redirected = true
			break
		}
		if redirected {
			continue
		}
		var out []dnsRR
		for _, rr := range rrs {
			if rr.name == name {
				out = append(out, rr)
			}
		}
		return out
	}
	return nil
}

func bitcoinTXT(rrs []dnsRR) (string, error) {
	var found string
	seen := false
	for _, rr := range rrs {
		if rr.typ != dnsTypeTXT {
			continue
		}
		var b []byte
		for _, part := range rr.txt {
			b = append(b, part...)
		}
		if len(b) >= len("bitcoin:") && strings.EqualFold(string(b[:len("bitcoin:")]), "bitcoin:") {
			if seen {
				return "", proofError{"Multiple TXT records existed for the HRN, which is invalid"}
			}
			seen = true
			found = string(b)
		}
	}
	if !seen {
		return "", proofError{"No validated TXT record found"}
	}
	if !utf8.ValidString(found) {
		return "", proofError{"TXT record contained an invalid string"}
	}
	return found, nil
}

func authenticatedBitcoinURI(proof []byte, qname string, now time.Time) (string, error) {
	rrs, err := parseProof(proof)
	if err != nil {
		return "", proofError{"DNSSEC signatures were invalid"}
	}
	verified, err := verifyRRStream(rrs)
	if err != nil {
		if errors.Is(err, errDNSUnsupported) {
			return "", proofError{"DNSSEC signatures use an unsupported algorithm"}
		}
		return "", proofError{"DNSSEC signatures were invalid"}
	}
	unix := uint64(now.Unix())
	if unix < verified.validFrom {
		return "", proofError{"Some DNSSEC records are not yet valid. Check your system clock."}
	}
	if unix > verified.expires {
		return "", proofError{"Some DNSSEC records are expired. Check your system clock."}
	}
	return bitcoinTXT(resolveCNAME(verified.rrs, strings.ToLower(qname)))
}
