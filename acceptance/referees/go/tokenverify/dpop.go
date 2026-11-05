package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"slices"
	"strings"
)

// Named results of the dpop mode. Each rejection maps to one numbered check in
// RFC 9449 section 4.3. Check 1 (one DPoP header field) belongs to an HTTP
// server, and this tool receives the proof as one flag.
const (
	codeDPoPOK        = "DPOP_OK"
	codeDPoPMalformed = "DPOP_MALFORMED"      // Check 2.
	codeDPoPMissing   = "DPOP_MISSING_CLAIM"  // Check 3.
	codeDPoPBadTyp    = "DPOP_BAD_TYP"        // Check 4.
	codeDPoPBadAlg    = "DPOP_BAD_ALG"        // Check 5.
	codeDPoPBadSig    = "DPOP_BAD_SIGNATURE"  // Check 6.
	codeDPoPBadJWK    = "DPOP_BAD_JWK"        // Checks 5 and 7.
	codeDPoPHTM       = "DPOP_HTM_MISMATCH"   // Check 8.
	codeDPoPHTU       = "DPOP_HTU_MISMATCH"   // Check 9.
	codeDPoPNonce     = "DPOP_NONCE_MISMATCH" // Check 10.
	codeDPoPIAT       = "DPOP_IAT_WINDOW"     // Check 11.
	codeDPoPATH       = "DPOP_ATH_MISMATCH"   // Check 12.
	codeDPoPJKT       = "DPOP_JKT_MISMATCH"   // Check 12.
	codeDPoPReplay    = "DPOP_REPLAY"         // Section 11.1.
)

type dpopRequest struct {
	method      string
	uri         string
	now         int64
	maxAge      int64
	nonce       string
	accessToken string
	jkt         string
	seenPath    string
}

type proofClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   *int64 `json:"iat"`
	Nonce string `json:"nonce"`
	ATH   string `json:"ath"`
}

// proofCheck carries one proof through the check list.
type proofCheck struct {
	req    dpopRequest
	jws    *compactJWS
	key    *proofKey
	claims proofClaims
}

// verifyDPoP runs the checks in order and stops at the first rejection. A check
// returns nil on a pass. The replay check runs last, so a rejected proof never
// burns its id.
func verifyDPoP(proof string, req dpopRequest) (result, error) {
	if req.method == "" || req.uri == "" {
		return result{}, errors.New("dpop mode needs -htm and -htu")
	}
	jws, err := parseCompact(proof)
	if err != nil {
		return reject(codeDPoPMalformed, "%v", err), nil
	}
	check := &proofCheck{req: req, jws: jws}
	steps := []func() *result{
		check.typ, check.alg, check.jwk, check.signature, check.parseClaims,
		check.method, check.uri, check.nonce, check.issuedAt, check.tokenHash,
		check.keyBinding, check.replay,
	}
	for _, step := range steps {
		if rejected := step(); rejected != nil {
			return *rejected, nil
		}
	}
	return result{Event: "result", Code: codeDPoPOK, Thumbprint: check.key.thumbprint()}, nil
}

func fail(code, format string, args ...any) *result {
	r := reject(code, format, args...)
	return &r
}

func (c *proofCheck) typ() *result {
	if typ := c.jws.headerString("typ"); typ != "dpop+jwt" {
		return fail(codeDPoPBadTyp, "typ %q, want dpop+jwt", typ)
	}
	return nil
}

// alg allows the two asymmetric algorithms this tool can verify. A proof with
// none or an HMAC algorithm stops here.
func (c *proofCheck) alg() *result {
	if alg := c.jws.headerString("alg"); alg != "EdDSA" && alg != "ES256" {
		return fail(codeDPoPBadAlg, "alg %q, want EdDSA or ES256", alg)
	}
	return nil
}

func (c *proofCheck) jwk() *result {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(c.jws.header["jwk"], &members); err != nil {
		return fail(codeDPoPBadJWK, "jwk header: %v", err)
	}
	key, err := parseProofKey(members)
	if err != nil {
		return fail(codeDPoPBadJWK, "%v", err)
	}
	if key.alg != c.jws.headerString("alg") {
		return fail(codeDPoPBadJWK, "jwk type does not match alg")
	}
	c.key = key
	return nil
}

func (c *proofCheck) signature() *result {
	if !c.key.verify(c.jws.signingInput, c.jws.signature) {
		return fail(codeDPoPBadSig, "signature does not verify under the jwk header")
	}
	return nil
}

func (c *proofCheck) parseClaims() *result {
	if err := json.Unmarshal(c.jws.payload, &c.claims); err != nil {
		return fail(codeDPoPMalformed, "claims: %v", err)
	}
	if c.claims.JTI == "" || c.claims.HTM == "" || c.claims.HTU == "" || c.claims.IAT == nil {
		return fail(codeDPoPMissing, "jti, htm, htu, and iat are required")
	}
	return nil
}

func (c *proofCheck) method() *result {
	if c.claims.HTM != c.req.method {
		return fail(codeDPoPHTM, "htm %q, request %q", c.claims.HTM, c.req.method)
	}
	return nil
}

func (c *proofCheck) uri() *result {
	claim, err := normalizeURI(c.claims.HTU)
	if err != nil {
		return fail(codeDPoPHTU, "htu: %v", err)
	}
	request, err := normalizeURI(c.req.uri)
	if err != nil {
		return fail(codeDPoPHTU, "-htu: %v", err)
	}
	if claim != request {
		return fail(codeDPoPHTU, "htu %q, request %q", claim, request)
	}
	return nil
}

// normalizeURI applies the RFC 3986 syntax and scheme steps that section 4.3
// recommends, and drops the query and fragment it says to ignore.
func normalizeURI(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Host = dropDefaultPort(u.Scheme, u.Host)
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func dropDefaultPort(scheme, host string) string {
	switch scheme {
	case "https":
		return strings.TrimSuffix(host, ":443")
	case "http":
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

func (c *proofCheck) nonce() *result {
	if c.req.nonce != "" && c.claims.Nonce != c.req.nonce {
		return fail(codeDPoPNonce, "nonce %q, server issued %q", c.claims.Nonce, c.req.nonce)
	}
	return nil
}

func (c *proofCheck) issuedAt() *result {
	distance := c.req.now - *c.claims.IAT
	if distance > c.req.maxAge || -distance > c.req.maxAge {
		return fail(codeDPoPIAT, "iat %d is %d s from now, limit %d", *c.claims.IAT, distance, c.req.maxAge)
	}
	return nil
}

func (c *proofCheck) tokenHash() *result {
	if c.req.accessToken == "" {
		return nil
	}
	digest := sha256.Sum256([]byte(c.req.accessToken))
	if want := b64.EncodeToString(digest[:]); c.claims.ATH != want {
		return fail(codeDPoPATH, "ath %q, access token hashes to %q", c.claims.ATH, want)
	}
	return nil
}

func (c *proofCheck) keyBinding() *result {
	if c.req.jkt != "" && c.key.thumbprint() != c.req.jkt {
		return fail(codeDPoPJKT, "proof key %q, token bound to %q", c.key.thumbprint(), c.req.jkt)
	}
	return nil
}

// replay records used proof ids per key in a file, one per line, so the check
// spans separate runs of this tool.
func (c *proofCheck) replay() *result {
	if c.req.seenPath == "" {
		return nil
	}
	entry := c.key.thumbprint() + " " + c.claims.JTI
	seen, err := os.ReadFile(c.req.seenPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(codeDPoPReplay, "cannot read -seen file: %v", err)
	}
	if slices.Contains(strings.Split(string(seen), "\n"), entry) {
		return fail(codeDPoPReplay, "jti %q already used", c.claims.JTI)
	}
	if err := appendLine(c.req.seenPath, entry); err != nil {
		return fail(codeDPoPReplay, "cannot write -seen file: %v", err)
	}
	return nil
}

func appendLine(path, line string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = fmt.Fprintln(file, line)
	return err
}

// proofKey is a public JWK after validation.
type proofKey struct {
	alg       string
	public    any
	canonical string // RFC 7638 member string.
}

// Member names that mark a JWK as holding private or symmetric key material.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

func parseProofKey(members map[string]json.RawMessage) (*proofKey, error) {
	for _, name := range privateMembers {
		if _, present := members[name]; present {
			return nil, fmt.Errorf("jwk holds private member %q", name)
		}
	}
	kty := jwkString(members, "kty")
	crv := jwkString(members, "crv")
	switch {
	case kty == "OKP" && crv == "Ed25519":
		return okpKey(members)
	case kty == "EC" && crv == "P-256":
		return ecKey(members)
	}
	return nil, fmt.Errorf("unsupported jwk kty %q crv %q", kty, crv)
}

func jwkString(members map[string]json.RawMessage, name string) string {
	var value string
	if err := json.Unmarshal(members[name], &value); err != nil {
		return ""
	}
	return value
}

func okpKey(members map[string]json.RawMessage) (*proofKey, error) {
	x := jwkString(members, "x")
	raw, err := b64.DecodeString(x)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("jwk x is not a 32-byte Ed25519 key")
	}
	canonical := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, x)
	return &proofKey{alg: "EdDSA", public: ed25519.PublicKey(raw), canonical: canonical}, nil
}

func ecKey(members map[string]json.RawMessage) (*proofKey, error) {
	x, y := jwkString(members, "x"), jwkString(members, "y")
	rawX, errX := b64.DecodeString(x)
	rawY, errY := b64.DecodeString(y)
	if errX != nil || errY != nil || len(rawX) != 32 || len(rawY) != 32 {
		return nil, errors.New("jwk x and y are not 32-byte coordinates")
	}
	point := slices.Concat([]byte{4}, rawX, rawY)
	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("jwk point: %w", err)
	}
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, x, y)
	return &proofKey{alg: "ES256", public: public, canonical: canonical}, nil
}

// thumbprint is the RFC 7638 value, the form RFC 9449 uses for jkt.
func (k *proofKey) thumbprint() string {
	digest := sha256.Sum256([]byte(k.canonical))
	return b64.EncodeToString(digest[:])
}

func (k *proofKey) verify(input, signature []byte) bool {
	switch public := k.public.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(public, input, signature)
	case *ecdsa.PublicKey:
		return verifyES256(public, input, signature)
	}
	return false
}

// verifyES256 takes the JWS form of the signature: R and S, 32 bytes each.
func verifyES256(public *ecdsa.PublicKey, input, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	digest := sha256.Sum256(input)
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	return ecdsa.Verify(public, digest[:], r, s)
}
