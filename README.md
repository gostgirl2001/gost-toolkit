# Local GOST Toolkit — Tkinter UI

For hashing, key generation, signing, verification, encryption, and decryption.

## Capabilities
- Hash text/files with GOST R 34.11-2012: 256 or 512 bit
- Generate GOST R 34.10-2012 keypairs
- Sign & verify messages (sign uses private key; verify uses public key)
- Encrypt & decrypt text using Kuznechik or Magma in CTR mode (key = 32 bytes, IV = 8 bytes)

## Notes
- CTR requires a unique IV for every encryption with the same key  
- Sign/verify hashes your message with GOST R 34.11-2012 before applying the signature  

## To run
pip install gostcrypto==1.2.5 (if not installed)
python gost_toolkit.py
