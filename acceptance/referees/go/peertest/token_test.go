package peertest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Published vectors, copied from the RFC text (fetched 2026-11-04).
const (
	rfc8037Key = `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	rfc8037JWS = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc." +
		"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"

	rfc9449Header = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik" +
		"VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR" +
		"nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE" +
		"QSIsImNydiI6IlAtMjU2In19"
	// RFC 9449 figure 2: POST https://server.example.com/token, iat 1562262616.
	rfc9449Token = rfc9449Header + ".eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj" +
		"oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia" +
		"WF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg" +
		"4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
	// RFC 9449 figure 13: GET with ath, iat 1562262618.
	rfc9449Resource = rfc9449Header + ".eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIj" +
		"oiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0Z" +
		"WRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNF" +
		"c05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71E" +
		"OptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA"
	rfc9449Jkt         = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	rfc9449AccessToken = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
)

func tokenResult(t *testing.T, wantExit int, args ...string) map[string]any {
	t.Helper()
	stdout, stderr, code := runTool(t, referee("tokenverify"), args...)
	if code != wantExit {
		t.Fatalf("exit %d, want %d; stdout %s stderr %s", code, wantExit, stdout, stderr)
	}
	return lastJSON(t, stdout)
}

func TestTokenVerifyRFC8037Vector(t *testing.T) {
	pub := writeFile(t, t.TempDir(), "issuer.jwk", []byte(rfc8037Key))
	event := tokenResult(t, 0, "-pub", pub, "-token", rfc8037JWS)
	wantField(t, event, "code", "TOKEN_OK")
	wantField(t, event, "payload", "Example of Ed25519 signing")

	// One field differs in each attack. Each gets its own name.
	parts := strings.Split(rfc8037JWS, ".")
	none := b64url([]byte(`{"alg":"none"}`)) + "." + parts[1] + "." + parts[2]
	wantField(t, tokenResult(t, 1, "-pub", pub, "-token", none), "code", "TOKEN_BAD_ALG")
	otherPayload := parts[0] + "." + b64url([]byte("Example of Ed25519 signinG")) + "." + parts[2]
	wantField(t, tokenResult(t, 1, "-pub", pub, "-token", otherPayload), "code", "TOKEN_BAD_SIGNATURE")
	wantField(t, tokenResult(t, 1, "-pub", pub, "-token", "a.b"), "code", "TOKEN_MALFORMED")
	crit := b64url([]byte(`{"alg":"EdDSA","crit":["x"]}`)) + "." + parts[1] + "." + parts[2]
	wantField(t, tokenResult(t, 1, "-pub", pub, "-token", crit), "code", "TOKEN_BAD_HEADER")
}

// OpenSSL makes the key and the signature, so the check runs against a signer
// that shares nothing with Go. The public key file is OpenSSL's PEM.
func TestTokenVerifyOpenSSLSigned(t *testing.T) {
	openssl := opensslPath(t)
	dir := t.TempDir()
	key, pub := filepath.Join(dir, "k.pem"), filepath.Join(dir, "p.pem")
	mustRun(t, openssl, "genpkey", "-algorithm", "ed25519", "-out", key)
	mustRun(t, openssl, "pkey", "-in", key, "-pubout", "-out", pub)
	token := opensslSign(t, openssl, key, dir, `{"alg":"EdDSA","typ":"JWT"}`, `{"sub":"clerk","role":"teller"}`)

	event := tokenResult(t, 0, "-pub", pub, "-token", token)
	wantField(t, event, "code", "TOKEN_OK")
	wantContains(t, event["payload"].(string), "teller")

	otherKey := filepath.Join(dir, "k2.pem")
	mustRun(t, openssl, "genpkey", "-algorithm", "ed25519", "-out", otherKey)
	forged := opensslSign(t, openssl, otherKey, dir, `{"alg":"EdDSA","typ":"JWT"}`, `{"sub":"clerk","role":"teller"}`)
	wantField(t, tokenResult(t, 1, "-pub", pub, "-token", forged), "code", "TOKEN_BAD_SIGNATURE")
}

func opensslSign(t *testing.T, openssl, key, dir, header, payload string) string {
	t.Helper()
	input := b64url([]byte(header)) + "." + b64url([]byte(payload))
	in, out := filepath.Join(dir, "in.bin"), filepath.Join(dir, "sig.bin")
	if err := os.WriteFile(in, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRun(t, openssl, "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", in, "-out", out)
	signature, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64url(signature)
}

func mustRun(t *testing.T, path string, args ...string) {
	t.Helper()
	stdout, stderr, code := runTool(t, path, args...)
	if code != 0 {
		t.Fatalf("%v: exit %d\n%s\n%s", args, code, stdout, stderr)
	}
}

func dpopArgs(proof, method, uri string, now int, rest ...string) []string {
	args := []string{"-mode", "dpop", "-token", proof, "-htm", method, "-htu", uri, "-now", fmt.Sprint(now)}
	return append(args, rest...)
}

// The RFC 9449 proofs pass, including the published thumbprint and ath.
func TestDPoPRFC9449Vectors(t *testing.T) {
	const tokenURI = "https://server.example.com/token"
	const resourceURI = "https://resource.example.org/protectedresource"
	event := tokenResult(t, 0, dpopArgs(rfc9449Token, "POST", tokenURI, 1562262620, "-jkt", rfc9449Jkt)...)
	wantField(t, event, "code", "DPOP_OK")
	wantField(t, event, "jkt", rfc9449Jkt)

	tokenResult(t, 0, dpopArgs(rfc9449Resource, "GET", resourceURI, 1562262620,
		"-access-token", rfc9449AccessToken, "-jkt", rfc9449Jkt)...)
	// Section 4.3 ignores query and fragment, and normalizes case and default port.
	tokenResult(t, 0, dpopArgs(rfc9449Token, "POST", "HTTPS://SERVER.example.com:443/token?x=1#f", 1562262620)...)

	rejections := []struct {
		name, code string
		args       []string
	}{
		{"method", "DPOP_HTM_MISMATCH", dpopArgs(rfc9449Token, "GET", tokenURI, 1562262620)},
		{"uri", "DPOP_HTU_MISMATCH", dpopArgs(rfc9449Token, "POST", tokenURI+"2", 1562262620)},
		{"late", "DPOP_IAT_WINDOW", dpopArgs(rfc9449Token, "POST", tokenURI, 1562262616+61)},
		{"early", "DPOP_IAT_WINDOW", dpopArgs(rfc9449Token, "POST", tokenURI, 1562262616-61)},
		{"bound key", "DPOP_JKT_MISMATCH", dpopArgs(rfc9449Token, "POST", tokenURI, 1562262620, "-jkt", "AAAA")},
		{"token hash", "DPOP_ATH_MISMATCH", dpopArgs(rfc9449Resource, "GET", resourceURI, 1562262620, "-access-token", "other")},
		{"nonce", "DPOP_NONCE_MISMATCH", dpopArgs(rfc9449Token, "POST", tokenURI, 1562262620, "-nonce", "abc")},
	}
	for _, rejection := range rejections {
		t.Run(rejection.name, func(t *testing.T) {
			wantField(t, tokenResult(t, 1, rejection.args...), "code", rejection.code)
		})
	}
}

// A replay is the same proof twice. The first use passes and the second is named.
// The seen file carries the state between two runs of the tool.
func TestDPoPReplay(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "seen")
	args := dpopArgs(rfc9449Token, "POST", "https://server.example.com/token", 1562262620, "-seen", seen)
	wantField(t, tokenResult(t, 0, args...), "code", "DPOP_OK")
	wantField(t, tokenResult(t, 1, args...), "code", "DPOP_REPLAY")
}

// Proofs built here with Ed25519, each changed in one field from a passing control.
func TestDPoPHeaderChecks(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64url(pub)}
	claims := map[string]any{"jti": "one", "htm": "POST", "htu": "https://a.example/t", "iat": 1000}
	sign := func(header, payload map[string]any) string {
		input := b64url(mustJSON(t, header)) + "." + b64url(mustJSON(t, payload))
		return input + "." + b64url(ed25519.Sign(priv, []byte(input)))
	}
	check := func(header, payload map[string]any) []string {
		return dpopArgs(sign(header, payload), "POST", "https://a.example/t", 1001)
	}
	header := func(typ, alg string, key any) map[string]any {
		return map[string]any{"typ": typ, "alg": alg, "jwk": key}
	}
	withPrivate := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64url(pub), "d": b64url(priv.Seed())}
	withoutJTI := map[string]any{"htm": "POST", "htu": "https://a.example/t", "iat": 1000}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64url(otherPub)}

	wantField(t, tokenResult(t, 0, check(header("dpop+jwt", "EdDSA", jwk), claims)...), "code", "DPOP_OK")
	rejections := []struct {
		name, code string
		args       []string
	}{
		{"typ", "DPOP_BAD_TYP", check(header("JWT", "EdDSA", jwk), claims)},
		{"alg none", "DPOP_BAD_ALG", check(header("dpop+jwt", "none", jwk), claims)},
		{"alg hmac", "DPOP_BAD_ALG", check(header("dpop+jwt", "HS256", jwk), claims)},
		{"private key in jwk", "DPOP_BAD_JWK", check(header("dpop+jwt", "EdDSA", withPrivate), claims)},
		{"alg and key disagree", "DPOP_BAD_JWK", check(header("dpop+jwt", "ES256", jwk), claims)},
		{"other key", "DPOP_BAD_SIGNATURE", check(header("dpop+jwt", "EdDSA", otherKey), claims)},
		{"missing jti", "DPOP_MISSING_CLAIM", check(header("dpop+jwt", "EdDSA", jwk), withoutJTI)},
	}
	for _, rejection := range rejections {
		t.Run(rejection.name, func(t *testing.T) {
			wantField(t, tokenResult(t, 1, rejection.args...), "code", rejection.code)
		})
	}
}

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
