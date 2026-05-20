package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func main() {
	pemData, err := os.ReadFile("cert.pem")
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("Failed to decode CERTIFICATE PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}

	// PKIX works for both RSA and ECDSA
	pkixBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		log.Fatalf("Failed to marshal PKIX public key: %v", err)
	}
	pkixPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixBytes,
	})

	fmt.Println("=== PKIX (BEGIN PUBLIC KEY) ===")
	fmt.Print(string(pkixPEM))

	// PKCS#1 only works for RSA
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pkcs1Bytes := x509.MarshalPKCS1PublicKey(key)
		pkcs1PEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pkcs1Bytes,
		})
		fmt.Println("=== PKCS#1 (BEGIN RSA PUBLIC KEY) ===")
		fmt.Print(string(pkcs1PEM))

	case *ecdsa.PublicKey:
		fmt.Println("=== PKCS#1 ===")
		fmt.Println("Not available — ECDSA keys have no PKCS#1 format")
	}
}
