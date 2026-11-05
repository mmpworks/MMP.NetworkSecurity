package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Named results of the jws mode.
const (
	codeTokenOK        = "TOKEN_OK"
	codeTokenMalformed = "TOKEN_MALFORMED"
	codeTokenBadAlg    = "TOKEN_BAD_ALG"
	codeTokenBadHeader = "TOKEN_BAD_HEADER"
	codeTokenBadSig    = "TOKEN_BAD_SIGNATURE"
)

// b64 refuses padding and stray trailing bits, so one token has one encoding.
var b64 = base64.RawURLEncoding.Strict()

// compactJWS is a token split into its three parts and decoded.
type compactJWS struct {
	header       map[string]json.RawMessage
	payload      []byte
	signature    []byte
	signingInput []byte
}

func parseCompact(token string) (*compactJWS, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%d parts, want 3", len(parts))
	}
	rawHeader, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	jws := &compactJWS{signingInput: []byte(parts[0] + "." + parts[1])}
	if err := json.Unmarshal(rawHeader, &jws.header); err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	if jws.payload, err = b64.DecodeString(parts[1]); err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	if jws.signature, err = b64.DecodeString(parts[2]); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	return jws, nil
}

// headerString returns a string header member, or "" when absent or not a string.
func (j *compactJWS) headerString(name string) string {
	var value string
	if err := json.Unmarshal(j.header[name], &value); err != nil {
		return ""
	}
	return value
}

func verifyJWS(pubPath, token string) (result, error) {
	if pubPath == "" {
		return result{}, errors.New("-pub is required")
	}
	pub, err := readPublicKey(pubPath)
	if err != nil {
		return result{}, err
	}
	jws, err := parseCompact(token)
	if err != nil {
		return reject(codeTokenMalformed, "%v", err), nil
	}
	if alg := jws.headerString("alg"); alg != "EdDSA" {
		return reject(codeTokenBadAlg, "alg %q, want EdDSA", alg), nil
	}
	// RFC 7515 section 4.1.11: a verifier must reject a crit it does not know.
	if _, present := jws.header["crit"]; present {
		return reject(codeTokenBadHeader, "crit header present"), nil
	}
	if !ed25519.Verify(pub, jws.signingInput, jws.signature) {
		return reject(codeTokenBadSig, "signature does not verify"), nil
	}
	return result{Event: "result", Code: codeTokenOK, Payload: string(jws.payload)}, nil
}

// readPublicKey accepts PEM (SPKI) or a JWK, chosen by the file's first byte.
func readPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		return ed25519FromJWK(data)
	}
	return ed25519FromPEM(data)
}

func ed25519FromPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("public key file holds no PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want Ed25519", parsed)
	}
	return key, nil
}

func ed25519FromJWK(data []byte) (ed25519.PublicKey, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, err
	}
	key, err := parseProofKey(members)
	if err != nil {
		return nil, err
	}
	edKey, ok := key.public.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("JWK is %T, want Ed25519", key.public)
	}
	return edKey, nil
}
