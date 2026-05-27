package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
)

var ErrPKCS1NotSupported = errors.New("PKCS#1 is only defined for RSA public keys")

func parseCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE PEM block, got %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func encodePKIX(pub any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

func encodePKCS1(pub any) ([]byte, error) {
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, ErrPKCS1NotSupported
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(rsaKey),
	}), nil
}

func main() {
	pemData, err := os.ReadFile("cert.pem")
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	cert, err := parseCertificate(pemData)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}

	pkixPEM, err := encodePKIX(cert.PublicKey)
	if err != nil {
		log.Fatalf("Failed to marshal PKIX public key: %v", err)
	}
	fmt.Println("=== PKIX (BEGIN PUBLIC KEY) ===")
	fmt.Print(string(pkixPEM))

	pkcs1PEM, err := encodePKCS1(cert.PublicKey)
	switch {
	case err == nil:
		fmt.Println("=== PKCS#1 (BEGIN RSA PUBLIC KEY) ===")
		fmt.Print(string(pkcs1PEM))
	case errors.Is(err, ErrPKCS1NotSupported):
		fmt.Println("=== PKCS#1 ===")
		if _, isECDSA := cert.PublicKey.(*ecdsa.PublicKey); isECDSA {
			fmt.Println("Not available — ECDSA keys have no PKCS#1 format")
		} else {
			fmt.Println("Not available — PKCS#1 is only defined for RSA keys")
		}
	default:
		log.Fatalf("Failed to encode PKCS#1 public key: %v", err)
	}
}
