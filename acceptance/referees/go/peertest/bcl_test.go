package peertest

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const crossCheckRounds = 200

// oracle is one line-protocol child process: the BCL oracle or pycheck.py.
type oracle struct {
	in  io.WriteCloser
	out *bufio.Scanner
}

func startOracle(t *testing.T, path string, args ...string) *oracle {
	t.Helper()
	cmd := exec.Command(path, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	return &oracle{in: stdin, out: scanner}
}

func (o *oracle) ask(t *testing.T, request map[string]any) map[string]any {
	t.Helper()
	if _, err := o.in.Write(append(mustJSON(t, request), '\n')); err != nil {
		t.Fatal(err)
	}
	if !o.out.Scan() {
		t.Fatalf("no answer to %v: %v", request, o.out.Err())
	}
	var response map[string]any
	if err := json.Unmarshal(o.out.Bytes(), &response); err != nil {
		t.Fatalf("%q: %v", o.out.Text(), err)
	}
	return response
}

// bytesOf reads a hex field from a good response and fails on an error response.
func (o *oracle) bytesOf(t *testing.T, request map[string]any, field string) []byte {
	t.Helper()
	response := o.ask(t, request)
	text, ok := response[field].(string)
	if !ok {
		t.Fatalf("%v answered %v", request, response)
	}
	return decodeHex(t, text)
}

func startBCL(t *testing.T) *oracle {
	t.Helper()
	dir := t.TempDir()
	build := exec.Command("dotnet", "build", "../../bcl", "-c", "Release", "-o", dir, "--nologo", "-v", "q")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("dotnet build: %v\n%s", err, out)
	}
	return startOracle(t, filepath.Join(dir, "NetSec.Referees.Bcl.exe"))
}

func hx(data []byte) string { return hex.EncodeToString(data) }

// Python covers hash, HMAC, and HKDF. Random inputs include empty ones, and both
// oracles must return the same bytes.
func TestBCLAgainstPython(t *testing.T) {
	bcl := startBCL(t)
	python := startOracle(t, "python", "-I", filepath.Join("testdata", "pycheck.py"))
	t.Run("hash", func(t *testing.T) {
		algs := []string{"md5", "sha1", "sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"}
		for _, alg := range algs {
			for round := range crossCheckRounds {
				request := map[string]any{"op": "hash", "alg": alg, "data": hx(randomBytes(t, round))}
				wantSameAnswer(t, bcl, python, request, "digest")
			}
		}
	})
	t.Run("shake", func(t *testing.T) {
		for _, alg := range []string{"shake128", "shake256"} {
			for round := range crossCheckRounds {
				request := map[string]any{"op": "hash", "alg": alg, "data": hx(randomBytes(t, round)), "length": 1 + round}
				wantSameAnswer(t, bcl, python, request, "digest")
			}
		}
	})
	t.Run("hmac", func(t *testing.T) {
		for _, alg := range []string{"sha1", "sha256", "sha384", "sha512"} {
			for round := range crossCheckRounds {
				request := map[string]any{"op": "hmac", "alg": alg, "key": hx(randomBytes(t, 1+round)), "data": hx(randomBytes(t, round))}
				wantSameAnswer(t, bcl, python, request, "mac")
			}
		}
	})
	t.Run("hkdf", func(t *testing.T) {
		for _, alg := range []string{"sha1", "sha256", "sha384", "sha512"} {
			for round := range crossCheckRounds {
				request := map[string]any{
					"op": "hkdf", "alg": alg, "ikm": hx(randomBytes(t, 1+round%80)),
					"salt": hx(randomBytes(t, round%64)), "info": hx(randomBytes(t, round%32)), "length": 1 + round,
				}
				wantSameAnswer(t, bcl, python, request, "okm")
			}
		}
	})
}

func wantSameAnswer(t *testing.T, a, b *oracle, request map[string]any, field string) {
	t.Helper()
	if x, y := a.bytesOf(t, request, field), b.bytesOf(t, request, field); !bytes.Equal(x, y) {
		t.Fatalf("%v: %x, %x", request, x, y)
	}
}

// Published vectors, so the BCL also meets an anchor Python and Go did not supply.
func TestBCLPublishedVectors(t *testing.T) {
	bcl := startBCL(t)
	sequence := "000102030405060708090a0b0c0d0e0f"
	zero16 := make([]byte, 16)
	vectors := []struct {
		name    string
		request map[string]any
		field   string
		want    string
	}{
		{"FIPS 197 C.1", map[string]any{"op": "aes-ecb-encrypt", "key": sequence, "data": "00112233445566778899aabbccddeeff"},
			"output", "69c4e0d86a7b0430d8cdb78070b4c55a"},
		{"GCM spec test case 2", map[string]any{"op": "aes-gcm-encrypt", "key": hx(zero16), "nonce": hx(make([]byte, 12)), "data": hx(zero16)},
			"tag", "ab6e47d42cec13bdf53a67b21257bddf"},
		{"RFC 4231 test 1 SHA-256", map[string]any{"op": "hmac", "alg": "sha256", "key": hx(bytes.Repeat([]byte{0x0b}, 20)), "data": hx([]byte("Hi There"))},
			"mac", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
		{"RFC 5869 test 1", map[string]any{"op": "hkdf", "alg": "sha256", "ikm": hx(bytes.Repeat([]byte{0x0b}, 22)),
			"salt": "000102030405060708090a0b0c", "info": "f0f1f2f3f4f5f6f7f8f9", "length": 42},
			"okm", "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"},
		{"FIPS 180-4 SHA-256 abc", map[string]any{"op": "hash", "alg": "sha256", "data": "616263"},
			"digest", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			if got := hx(bcl.bytesOf(t, vector.request, vector.field)); got != vector.want {
				t.Fatalf("got %s, want %s", got, vector.want)
			}
		})
	}
}

// Python's standard library has no AES, so the Go standard library is the second
// opinion for the modes.
func TestBCLAESAgainstGo(t *testing.T) {
	bcl := startBCL(t)
	for round := range crossCheckRounds {
		key := randomBytes(t, []int{16, 24, 32}[round%3])
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		data := randomBytes(t, 16*(1+round%16))
		checkECB(t, bcl, block, key, data)
		checkCBC(t, bcl, block, key, data)
		checkGCM(t, bcl, block, key, data, randomBytes(t, round%40))
	}
}

func checkECB(t *testing.T, bcl *oracle, block cipher.Block, key, data []byte) {
	t.Helper()
	want := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Encrypt(want[i:], data[i:])
	}
	got := bcl.bytesOf(t, map[string]any{"op": "aes-ecb-encrypt", "key": hx(key), "data": hx(data)}, "output")
	if !bytes.Equal(got, want) {
		t.Fatalf("ECB encrypt: %x, %x", got, want)
	}
	back := bcl.bytesOf(t, map[string]any{"op": "aes-ecb-decrypt", "key": hx(key), "data": hx(want)}, "output")
	if !bytes.Equal(back, data) {
		t.Fatal("ECB decrypt did not return the input")
	}
}

func checkCBC(t *testing.T, bcl *oracle, block cipher.Block, key, data []byte) {
	t.Helper()
	iv := randomBytes(t, aes.BlockSize)
	want := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(want, data)
	got := bcl.bytesOf(t, map[string]any{"op": "aes-cbc-encrypt", "key": hx(key), "iv": hx(iv), "data": hx(data)}, "output")
	if !bytes.Equal(got, want) {
		t.Fatalf("CBC encrypt: %x, %x", got, want)
	}
	back := bcl.bytesOf(t, map[string]any{"op": "aes-cbc-decrypt", "key": hx(key), "iv": hx(iv), "data": hx(want)}, "output")
	if !bytes.Equal(back, data) {
		t.Fatal("CBC decrypt did not return the input")
	}
}

func checkGCM(t *testing.T, bcl *oracle, block cipher.Block, key, data, aad []byte) {
	t.Helper()
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := randomBytes(t, 12)
	sealed := gcm.Seal(nil, nonce, data, aad)
	ciphertext, tag := sealed[:len(data)], sealed[len(data):]
	request := map[string]any{"op": "aes-gcm-encrypt", "key": hx(key), "nonce": hx(nonce), "aad": hx(aad), "data": hx(data)}
	response := bcl.ask(t, request)
	if response["output"] != hx(ciphertext) || response["tag"] != hx(tag) {
		t.Fatalf("GCM encrypt: %v, %x", response, sealed)
	}
	open := map[string]any{"op": "aes-gcm-decrypt", "key": hx(key), "nonce": hx(nonce), "aad": hx(aad), "data": hx(ciphertext), "tag": hx(tag)}
	if !bytes.Equal(bcl.bytesOf(t, open, "output"), data) {
		t.Fatal("GCM decrypt did not return the input")
	}
	badTag := bytes.Clone(tag)
	badTag[0] ^= 1
	open["tag"] = hx(badTag)
	if response := bcl.ask(t, open); response["error"] != "GCM_TAG_MISMATCH" {
		t.Fatalf("tampered tag answered %v", response)
	}
}

// HKDF gets one more check against the Go standard library, because the Python
// peer writes the two RFC steps by hand.
func TestBCLHKDFAgainstGo(t *testing.T) {
	bcl := startBCL(t)
	for round := range crossCheckRounds {
		ikm, salt := randomBytes(t, 1+round%80), randomBytes(t, 1+round%64)
		info := string(randomBytes(t, round%32))
		want, err := hkdf.Key(sha256.New, ikm, salt, info, 1+round)
		if err != nil {
			t.Fatal(err)
		}
		got := bcl.bytesOf(t, map[string]any{
			"op": "hkdf", "alg": "sha256", "ikm": hx(ikm), "salt": hx(salt), "info": hx([]byte(info)), "length": 1 + round,
		}, "okm")
		if !bytes.Equal(got, want) {
			t.Fatalf("round %d: %x, %x", round, got, want)
		}
	}
}

// ML-KEM-768 against Go's crypto/mlkem: same public key from one seed, each side
// decapsulates the other's ciphertext, and implicit rejection gives one answer.
func TestBCLMLKemAgainstGo(t *testing.T) {
	bcl := startBCL(t)
	info := bcl.ask(t, map[string]any{"op": "info"})
	wantField(t, info, "mlkem", true)
	for range crossCheckRounds {
		seed := randomBytes(t, mlkem.SeedSize)
		goKey, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			t.Fatal(err)
		}
		ek := goKey.EncapsulationKey().Bytes()
		keys := bcl.ask(t, map[string]any{"op": "mlkem768-keygen", "seed": hx(seed)})
		if keys["ek"] != hx(ek) {
			t.Fatal("encapsulation keys differ for one seed")
		}

		goSecret, goCiphertext := goKey.EncapsulationKey().Encapsulate()
		fromSeed := bcl.bytesOf(t, map[string]any{"op": "mlkem768-decaps", "seed": hx(seed), "ciphertext": hx(goCiphertext)}, "secret")
		if !bytes.Equal(fromSeed, goSecret) {
			t.Fatal("BCL decapsulation from the seed differs from Go encapsulation")
		}
		fromDK := bcl.bytesOf(t, map[string]any{"op": "mlkem768-decaps", "dk": keys["dk"], "ciphertext": hx(goCiphertext)}, "secret")
		if !bytes.Equal(fromDK, goSecret) {
			t.Fatal("BCL decapsulation from the expanded key differs from Go encapsulation")
		}

		sealed := bcl.ask(t, map[string]any{"op": "mlkem768-encaps", "ek": hx(ek)})
		ciphertext := decodeHex(t, sealed["ciphertext"].(string))
		secret, err := goKey.Decapsulate(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if hx(secret) != sealed["secret"] {
			t.Fatal("Go decapsulation differs from BCL encapsulation")
		}

		ciphertext[0] ^= 1
		rejected, err := goKey.Decapsulate(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		got := bcl.bytesOf(t, map[string]any{"op": "mlkem768-decaps", "seed": hx(seed), "ciphertext": hx(ciphertext)}, "secret")
		if !bytes.Equal(got, rejected) {
			t.Fatal("implicit rejection values differ")
		}
	}
}

// Failures carry a stable code, so a suite can branch on it.
func TestBCLNamedErrors(t *testing.T) {
	bcl := startBCL(t)
	cases := []struct {
		request map[string]any
		code    string
	}{
		{map[string]any{"id": 7, "op": "no-such-op"}, "UNKNOWN_OP"},
		{map[string]any{"op": "hash", "alg": "sha999", "data": ""}, "UNKNOWN_ALG"},
		{map[string]any{"op": "hash", "alg": "sha256"}, "BAD_REQUEST"},
		{map[string]any{"op": "hash", "alg": "sha256", "data": "zz"}, "BAD_REQUEST"},
	}
	for _, c := range cases {
		response := bcl.ask(t, c.request)
		wantField(t, response, "ok", false)
		wantField(t, response, "error", c.code)
	}
	if _, err := bcl.in.Write([]byte("not json\n")); err != nil {
		t.Fatal(err)
	}
	if !bcl.out.Scan() || !bytes.Contains(bcl.out.Bytes(), []byte("BAD_REQUEST")) {
		t.Fatalf("bad line answered %q", bcl.out.Text())
	}
}
