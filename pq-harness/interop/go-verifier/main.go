// go-verifier — the third independent KAT leg (SPEC §7.3b), using Go 1.27's
// standard-library crypto/mldsa (a different implementation lineage from the
// Rust fips204 and ml-dsa crates). It re-derives the draft §6 worked example
// from the same fixtures the Rust harness uses: keygen from the 32-byte seed
// reproduces the public key, deterministic signing reproduces the RRSIG, and
// Verify accepts it — all over the RRSIG signed-data the Rust lib.rs builds.
//
// No network. Fixtures live in ../../fixtures (machine-extracted from the draft).
// Run: go run . (requires Go >= 1.27 for crypto/mldsa)
package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// draft §6 seed 0x00..0x1f
func seed() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

func nameWire(name string) []byte {
	var out bytes.Buffer
	name = strings.TrimSuffix(name, ".")
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			l := strings.ToLower(label)
			out.WriteByte(byte(len(l)))
			out.WriteString(l)
		}
	}
	out.WriteByte(0)
	return out.Bytes()
}

func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func be32(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

// mxRdata: preference || uncompressed lowercased exchange name.
func mxRdata(pref uint16, exchange string) []byte {
	return append(be16(pref), nameWire(exchange)...)
}

// rrsigSignedData mirrors pq_harness::rrsig_signed_data exactly (RFC 4034
// §3.1.8.1): RRSIG RDATA minus signature, then the canonical RRset.
func rrsigSignedData() []byte {
	var m bytes.Buffer
	m.Write(be16(15))               // type covered: MX
	m.WriteByte(18)                 // algorithm
	m.WriteByte(2)                  // labels
	m.Write(be32(3600))             // orig TTL
	m.Write(be32(1440021600))       // expiration
	m.Write(be32(1438207200))       // inception
	m.Write(be16(59829))            // keytag
	m.Write(nameWire("example.com.")) // signer
	// single MX RR
	rdata := mxRdata(10, "mail.example.com.")
	m.Write(nameWire("example.com."))
	m.Write(be16(15))
	m.Write(be16(1)) // class IN
	m.Write(be32(3600))
	m.Write(be16(uint16(len(rdata))))
	m.Write(rdata)
	return m.Bytes()
}

func readFixture(name string) []byte {
	raw, err := os.ReadFile("../../fixtures/" + name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read fixture %s: %v\n", name, err)
		os.Exit(2)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad base64 in %s: %v\n", name, err)
		os.Exit(2)
	}
	return b
}

func fail(msg string) {
	fmt.Println("FAIL:", msg)
	os.Exit(1)
}

func main() {
	vecPub := readFixture("vector-pubkey.b64")
	vecSig := readFixture("vector-rrsig.b64")

	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed())
	if err != nil {
		fail("NewPrivateKey: " + err.Error())
	}
	pk := sk.PublicKey()

	// Leg 1: keygen reproduces the §6 public key.
	if !bytes.Equal(pk.Bytes(), vecPub) {
		fail("Go crypto/mldsa keygen != draft §6 public key")
	}
	fmt.Println("ok  keygen reproduces §6 public key (1312 B)")

	// Leg 2: keytag + DS derived from that key match the draft.
	rdata := append(append(be16(257), 3, 18), vecPub...)
	var ac uint32
	for i, b := range rdata {
		if i&1 == 1 {
			ac += uint32(b)
		} else {
			ac += uint32(b) << 8
		}
	}
	ac += (ac >> 16) & 0xFFFF
	if kt := uint16(ac & 0xFFFF); kt != 59829 {
		fail(fmt.Sprintf("keytag %d != 59829", kt))
	}
	dsInput := append(nameWire("example.com."), rdata...)
	ds := sha256.Sum256(dsInput)
	const wantDS = "812cb1a22af04380e2f72d91c06c14eb1a918cf30037a8a9c67497e9264b4bfa"
	if hex.EncodeToString(ds[:]) != wantDS {
		fail("DS digest != draft §6")
	}
	fmt.Println("ok  keytag 59829 and DS 812cb1a2…4bfa match the draft")

	msg := rrsigSignedData()

	// Leg 3: deterministic signing reproduces the §6 RRSIG byte-for-byte.
	sig, err := sk.SignDeterministic(msg, &mldsa.Options{})
	if err != nil {
		fail("SignDeterministic: " + err.Error())
	}
	if !bytes.Equal(sig, vecSig) {
		fail("Go deterministic RRSIG != draft §6 signature")
	}
	fmt.Println("ok  deterministic RRSIG reproduces §6 signature (2420 B)")

	// Leg 4: Verify accepts the §6 signature.
	if err := mldsa.Verify(pk, msg, vecSig, &mldsa.Options{}); err != nil {
		fail("Verify rejected the §6 RRSIG: " + err.Error())
	}
	fmt.Println("ok  Verify accepts the §6 RRSIG")

	// Negative controls.
	bad := append([]byte(nil), vecSig...)
	bad[100] ^= 0x01
	if mldsa.Verify(pk, msg, bad, &mldsa.Options{}) == nil {
		fail("Verify accepted a flipped-bit signature")
	}
	if mldsa.Verify(pk, msg, vecSig, &mldsa.Options{Context: "x"}) == nil {
		fail("Verify accepted a non-empty context (draft §4 requires empty)")
	}
	fmt.Println("ok  negative controls (bitflip, non-empty ctx) both rejected")

	fmt.Println("\nGO VERIFIER: all legs green — crypto/mldsa agrees with the Rust harness on the §6 vector")
}
