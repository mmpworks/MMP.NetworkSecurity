// sealwalk runs the verifier's own §7 walk (WalkAuditFileWithKey) on the sample
// custody chain, with a daily seal this program makes. The CLI's --audit-file path
// takes no seal, so a program must call the walk to reach steps 10 and 11.
// It reaches the repo through `go run -overlay` and adds no file to the repo.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/mmpworks/ffiec/core/constants"
	"github.com/mmpworks/ffiec/core/hkdf"
	"github.com/mmpworks/ffiec/core/signpayload"
	"github.com/mmpworks/ffiec/verifier/internal/verify"
)

// editedIndex is the row a key holder changes.
const (
	editedIndex = 2
	signVersion = "v1.0a"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	must(err)
	keyHex, err := os.ReadFile(os.Args[2])
	must(err)
	ikm, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	must(err)
	ikms := verify.IKMRegistry{1: ikm}

	realPub, realPriv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	ownPub, ownPriv, err := ed25519.GenerateKey(rand.Reader)
	must(err)

	base := load(raw)
	base.Seal = makeSeal(base, realPriv)
	report("intact chain, real seal", base, ikms, realPub)

	cut := load(raw)
	cut.Entries = cut.Entries[:len(cut.Entries)-1]
	cut.Seal = base.Seal
	report("last event cut, real seal", cut, ikms, realPub)

	changed := load(raw)
	rewrite(changed, ikm)
	changed.Seal = base.Seal
	report("rewritten with the key, real seal", changed, ikms, realPub)

	newRoot := load(raw)
	rewrite(newRoot, ikm)
	newRoot.Seal = base.Seal
	newRoot.Seal.MerkleRootHex = rootOf(newRoot)
	report("rewritten, root replaced, real signature", newRoot, ikms, realPub)

	own := load(raw)
	rewrite(own, ikm)
	own.Seal = makeSeal(own, ownPriv)
	report("rewritten, seal signed with the writer's own key, verified with the real public key", own, ikms, realPub)
	report("the same file, verified with the writer's public key", own, ikms, ownPub)
}

func load(raw []byte) *verify.AuditFile {
	af, out := verify.LoadAuditNDJSON(raw)
	if out.Status == "FAIL" {
		panic(out.Reason)
	}
	return af
}

// rewrite does what a holder of the master key can do: change one event, then
// make a new tag and link for it and for every event after it.
func rewrite(af *verify.AuditFile, ikm []byte) {
	info := []byte(constants.HKDFInfoBase + constants.InfoTenantSeparator + af.Header.TenantID)
	key := hkdf.Derive(ikm, []byte(constants.HKDFSalt), info, constants.HKDFOutputLength)

	event, err := hex.DecodeString(af.Entries[editedIndex].EventCanonicalHex)
	must(err)
	event = append(bytes.Clone(event), ' ') // One byte added to the event text is enough to test the seal.
	af.Entries[editedIndex].EventCanonicalHex = hex.EncodeToString(event)

	prev := make([]byte, 32)
	for i := range af.Entries {
		e := &af.Entries[i]
		canonical, err := hex.DecodeString(e.EventCanonicalHex)
		must(err)
		e.PrevHashHex = hex.EncodeToString(prev)
		mac := hmac.New(sha256.New, key)
		mac.Write(prev)
		mac.Write(canonical)
		prev = mac.Sum(nil)
		e.PayloadHashHex = hex.EncodeToString(prev)
	}
}

func rootOf(af *verify.AuditFile) string {
	leaves := make([][]byte, 0, len(af.Entries))
	for i := range af.Entries {
		tag, err := hex.DecodeString(af.Entries[i].PayloadHashHex)
		must(err)
		leaves = append(leaves, verify.MerkleLeafHash(tag))
	}
	return hex.EncodeToString(verify.MerkleTreeHash(leaves))
}

func makeSeal(af *verify.AuditFile, priv ed25519.PrivateKey) verify.AuditSeal {
	seal := verify.AuditSeal{
		MerkleRootHex:       rootOf(af),
		Algorithm:           "ed25519",
		SealDate:            "2026-11-06",
		FormatVersion:       af.Header.FormatVersion,
		SignPayloadVersion:  signVersion,
		Cadence:             "daily",
		DevMode:             true,
		TenantID:            af.Header.TenantID,
		HKDFInputsDigestHex: af.Header.HKDFInputsDigestHex,
	}
	version, err := signpayload.ParseVersion(signVersion)
	must(err)
	payload, err := signpayload.Build(signpayload.Seal{
		Version: version, Algorithm: seal.Algorithm, FormatVersion: seal.FormatVersion,
		TenantID: seal.TenantID, SealDate: seal.SealDate, MerkleRootHex: seal.MerkleRootHex,
		HKDFInputsDigest: seal.HKDFInputsDigestHex, Cadence: seal.Cadence, DevMode: seal.DevMode,
	})
	must(err)
	seal.SignPayloadHex = hex.EncodeToString(payload)
	seal.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	return seal
}

func report(name string, af *verify.AuditFile, ikms verify.IKMRegistry, pub ed25519.PublicKey) {
	out := verify.WalkAuditFileWithKey(af, ikms, pub)
	fmt.Printf("%s\n  Status: %s\n", name, out.Status)
	if out.Status != "PASS" {
		fmt.Printf("  Step: %s\n  Reason: %s\n", out.Step, out.Reason)
	}
	fmt.Printf("  ExitCode: %d\n\n", out.ExitCode)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
