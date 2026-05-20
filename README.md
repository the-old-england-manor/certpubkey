# certpubkey

A small Go utility that reads an X.509 SSL certificate and extracts its public key in both **PKIX** and **PKCS#1** formats.

## What it does

Given a PEM-encoded certificate, it outputs:

- `BEGIN PUBLIC KEY` — PKIX / SubjectPublicKeyInfo format (works for RSA and ECDSA)
- `BEGIN RSA PUBLIC KEY` — PKCS#1 format (RSA only)

## Background

SSL certificates embed a public key inside a larger X.509 structure containing metadata (subject, issuer, validity, signature, etc). This tool strips all of that away and gives you just the raw public key in the format you need.

See [PKCS#1 vs PKIX](#pkcs1-vs-pkix) below for a quick explanation of the two formats.

## Requirements

- Go 1.18+

## Usage

```bash
go run main.go
```

By default it reads from `cert.pem` in the current directory. You can adjust the filename in `main.go`.

**Example output:**

```
=== PKIX (BEGIN PUBLIC KEY) ===
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxJRn...
-----END PUBLIC KEY-----

=== PKCS#1 (BEGIN RSA PUBLIC KEY) ===
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAxJRn...
-----END RSA PUBLIC KEY-----
```

> **Note:** PKCS#1 output is only available for RSA keys. For ECDSA certificates, only the PKIX output is produced.

## PKCS#1 vs PKIX

|                         | PKCS#1                 | PKIX                               |
| ----------------------- | ---------------------- | ---------------------------------- |
| Defined by              | RSA Security           | IETF                               |
| Key types supported     | RSA only               | RSA, ECDSA, Ed25519, ...           |
| Contains algorithm info | No                     | Yes (OID inside)                   |
| PEM header              | `BEGIN RSA PUBLIC KEY` | `BEGIN PUBLIC KEY`                 |
| Used in                 | Legacy / older systems | TLS certificates, modern standards |

PKCS#1 contains just the raw RSA modulus and exponent. PKIX wraps the key in a `SubjectPublicKeyInfo` structure that also identifies the algorithm, making it format-agnostic.

## Writing to files

To write the keys to disk instead of stdout, uncomment these lines in `main.go`:

```go
// os.WriteFile("key_pkix.pem", pkixPEM, 0644)
// os.WriteFile("key_pkcs1.pem", pkcs1PEM, 0644)
```

## License

MIT — see [LICENSE](LICENSE)
