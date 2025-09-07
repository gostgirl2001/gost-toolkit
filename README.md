# Local GOST Toolkit — Tkinter UI

## Capabilities
- Hash text/files with GOST R 34.11-2012: 256 or 512 bit
- Generate GOST 34.10-2012 keypairs
- Sign & verify messages
- Encrypt & decrypt text in CTR mode
- PKCS#7 (CMS) sign/verify options via GOST-enabled OpenSSL, supports chain validation (CA bundle)
- OIDs / DER tools (PEM<->DER for certs/keys; TC26 OID scan)

## Notes
- CTR requires a unique IV for every encryption with the same key
- Requires gostcrypto==1.2.5 (Python) and OpenSSL 1.1.1u with GOST engine

## Important
- The use of CMS features requires a GOST-enabled OpenSSL build
- A prebuilt .deb package (openssl-gost) is available under Releases
