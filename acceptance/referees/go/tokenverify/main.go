// Command tokenverify checks a compact JWS or a DPoP proof with the standard
// library. It prints one JSON result line and exits 0 on the named OK result,
// 1 on any named rejection, and 2 on a usage error.
//
// The jws mode checks the signature and the header only (EdDSA, no crit). It
// prints the payload and leaves claim policy such as exp and aud to the suite.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"mmpworks.local/netsec/referees/internal/report"
)

type result struct {
	Event  string `json:"event"`
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
	// Payload holds the JWS payload as text. Thumbprint is the proof key's
	// RFC 7638 value. Each is present only on an OK result.
	Payload    string `json:"payload,omitempty"`
	Thumbprint string `json:"jkt,omitempty"`
}

func reject(code, format string, args ...any) result {
	return result{Event: "result", Code: code, Detail: fmt.Sprintf(format, args...)}
}

type options struct {
	mode  string
	pub   string
	token string
	dpop  dpopRequest
}

func main() {
	var o options
	var now int64
	flag.StringVar(&o.mode, "mode", "jws", "jws or dpop")
	flag.StringVar(&o.pub, "pub", "", "jws: issuer Ed25519 public key file, PEM (SPKI) or JWK")
	flag.StringVar(&o.token, "token", "", "the compact JWS, or the DPoP proof in dpop mode")
	flag.StringVar(&o.dpop.method, "htm", "", "dpop: HTTP method of the request")
	flag.StringVar(&o.dpop.uri, "htu", "", "dpop: HTTP URI of the request")
	flag.Int64Var(&now, "now", 0, "dpop: current time, Unix seconds (0: the clock)")
	flag.Int64Var(&o.dpop.maxAge, "max-age", 60, "dpop: largest iat distance from now, seconds")
	flag.StringVar(&o.dpop.nonce, "nonce", "", "dpop: nonce the server issued")
	flag.StringVar(&o.dpop.accessToken, "access-token", "", "dpop: access token, checked against ath")
	flag.StringVar(&o.dpop.jkt, "jkt", "", "dpop: thumbprint the access token is bound to")
	flag.StringVar(&o.dpop.seenPath, "seen", "", "dpop: file of used proof ids; a repeat gives DPOP_REPLAY")
	flag.Parse()
	o.dpop.now = resolveNow(now)

	out, err := o.dispatch()
	if err != nil {
		report.Usage(err)
	}
	report.Event(out)
	if out.Code != codeTokenOK && out.Code != codeDPoPOK {
		os.Exit(report.ExitRejected)
	}
}

func resolveNow(now int64) int64 {
	if now != 0 {
		return now
	}
	return time.Now().Unix()
}

func (o *options) dispatch() (result, error) {
	if o.token == "" {
		return result{}, fmt.Errorf("-token is required")
	}
	switch o.mode {
	case "jws":
		return verifyJWS(o.pub, o.token)
	case "dpop":
		return verifyDPoP(o.token, o.dpop)
	}
	return result{}, fmt.Errorf("unknown -mode %q", o.mode)
}
