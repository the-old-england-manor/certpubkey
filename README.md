# certpubkey

A small Go utility that reads an X.509 SSL certificate and extracts its public key in both **PKIX** and **PKCS#1** formats.

## What it does

Given a PEM-encoded certificate, it outputs:

- `BEGIN PUBLIC KEY` — PKIX / SubjectPublicKeyInfo format (works for RSA and ECDSA)
- `BEGIN RSA PUBLIC KEY` — PKCS#1 format (RSA only)

## Why this exists

Some TLS certificate vendors ship only the certificate and the private key — not the public key as a standalone file. If you have a device that wants the public key uploaded separately in PKIX or PKCS#1 PEM format (network switches sometimes do), there's no straight-from-vendor file for it, and extracting it by hand means chaining `openssl` commands on every cert rotation.

That's the gap that prompted this tool. Point `certpubkey` at the cert from the vendor, get back the public key in the format the device expects.

## Background

SSL certificates embed a public key inside a larger X.509 structure containing metadata (subject, issuer, validity, signature, etc). This tool strips all of that away and gives you just the raw public key in the format you need.

See [PKCS#1 vs PKIX](#pkcs1-vs-pkix) below for a quick explanation of the two formats.

## Requirements

- Go 1.21+

## Install

```bash
go install github.com/the-old-england-manor/certpubkey@latest
```

Replace `@latest` with a version tag (e.g. `@v0.1.0`) to pin to a specific release.

## Usage

```bash
go run . <path-to-cert.pem>
```

Or build once and reuse:

```bash
go build -o certpubkey
./certpubkey /path/to/cert.pem
```

The path to the PEM-encoded certificate is the first (and only) positional argument. The tool exits with a usage message if no path is given.

**Example output:**

```
=== PKIX ===

-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxJRn...
-----END PUBLIC KEY-----

=== PKCS#1 ===

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

## License

MIT — see [LICENSE](LICENSE)
