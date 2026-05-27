package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSelfSignedCertPEM(t *testing.T, key any) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	var pub any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	default:
		t.Fatalf("unsupported key type %T", key)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func TestParseCertificate(t *testing.T) {
	rsaKey := newRSAKey(t)
	ecdsaKey := newECDSAKey(t)

	t.Run("valid RSA cert", func(t *testing.T) {
		cert, err := parseCertificate(newSelfSignedCertPEM(t, rsaKey))
		require.NoError(t, err)
		assert.IsType(t, &rsa.PublicKey{}, cert.PublicKey)
	})

	t.Run("valid ECDSA cert", func(t *testing.T) {
		cert, err := parseCertificate(newSelfSignedCertPEM(t, ecdsaKey))
		require.NoError(t, err)
		assert.IsType(t, &ecdsa.PublicKey{}, cert.PublicKey)
	})

	t.Run("garbage bytes", func(t *testing.T) {
		_, err := parseCertificate([]byte("not a pem"))
		assert.Error(t, err)
	})

	t.Run("wrong PEM block type", func(t *testing.T) {
		wrong := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("data")})
		_, err := parseCertificate(wrong)
		assert.Error(t, err)
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := parseCertificate(nil)
		assert.Error(t, err)
	})
}

func TestEncodePKIX(t *testing.T) {
	rsaKey := newRSAKey(t)
	ecdsaKey := newECDSAKey(t)

	t.Run("RSA round-trip", func(t *testing.T) {
		out, err := encodePKIX(&rsaKey.PublicKey)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(out), "-----BEGIN PUBLIC KEY-----"))

		block, _ := pem.Decode(out)
		require.NotNil(t, block)
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		require.NoError(t, err)
		assert.True(t, rsaKey.PublicKey.Equal(parsed))
	})

	t.Run("ECDSA round-trip", func(t *testing.T) {
		out, err := encodePKIX(&ecdsaKey.PublicKey)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(out), "-----BEGIN PUBLIC KEY-----"))

		block, _ := pem.Decode(out)
		require.NotNil(t, block)
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		require.NoError(t, err)
		assert.True(t, ecdsaKey.PublicKey.Equal(parsed))
	})
}

func TestEncodePKCS1(t *testing.T) {
	rsaKey := newRSAKey(t)
	ecdsaKey := newECDSAKey(t)

	t.Run("RSA round-trip", func(t *testing.T) {
		out, err := encodePKCS1(&rsaKey.PublicKey)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(out), "-----BEGIN RSA PUBLIC KEY-----"))

		block, _ := pem.Decode(out)
		require.NotNil(t, block)
		parsed, err := x509.ParsePKCS1PublicKey(block.Bytes)
		require.NoError(t, err)
		assert.True(t, rsaKey.PublicKey.Equal(parsed))
	})

	t.Run("ECDSA returns sentinel error", func(t *testing.T) {
		_, err := encodePKCS1(&ecdsaKey.PublicKey)
		assert.ErrorIs(t, err, ErrPKCS1NotSupported)
	})
}
