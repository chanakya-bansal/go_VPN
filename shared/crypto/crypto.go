package crypto

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeyLen   = 32
	Overhead = chacha20poly1305.Overhead // 16-byte Poly1305 tag
)

// ---- X25519 ----

type KeyPair struct{ priv *ecdh.PrivateKey }

func NewKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{priv: priv}, nil
}

func (k *KeyPair) Public() []byte { return k.priv.PublicKey().Bytes() }

// Shared computes the DH secret. X25519 rejects low-order peer keys
// (all-zero output) with an error.
func (k *KeyPair) Shared(peerPub []byte) ([]byte, error) {
	pk, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return k.priv.ECDH(pk)
}

// ---- HKDF ----

// DeriveKeys expands the DH secret into one key per direction.
// The transcript (both public keys) is the salt.
func DeriveKeys(shared, clientPub, serverPub []byte) (c2s, s2c []byte, err error) {
	salt := append(append([]byte{}, clientPub...), serverPub...)
	okm, err := hkdf.Key(sha256.New, shared, salt, "govpn v1 traffic keys", 2*KeyLen)
	if err != nil {
		return nil, nil, err
	}
	return okm[:KeyLen], okm[KeyLen:], nil
}

// ---- HMAC (pre-shared key authentication) ----

func MAC(psk []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, psk)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func VerifyMAC(psk, tag []byte, parts ...[]byte) bool {
	return hmac.Equal(tag, MAC(psk, parts...))
}

// ---- AEAD ----

type Cipher struct{ aead cipher.AEAD }

func NewCipher(key []byte) (*Cipher, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: a}, nil
}

func nonce(ctr uint64) [12]byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// Seal appends ciphertext+tag to dst. dst may be plain[:0] to encrypt in place.
func (c *Cipher) Seal(dst, plain, hdr []byte, ctr uint64) []byte {
	n := nonce(ctr)
	return c.aead.Seal(dst, n[:], plain, hdr)
}

// Open appends the plaintext to dst. dst may be ct[:0] to decrypt in place.
func (c *Cipher) Open(dst, ct, hdr []byte, ctr uint64) ([]byte, error) {
	n := nonce(ctr)
	return c.aead.Open(dst, n[:], ct, hdr)
}