# Bytarith

**Bytarith** is a local-first short-key text encryption tool.

- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA-256 with 600,000 iterations
- Fresh 128-bit salt and 96-bit IV for every message
- Cryptographically random 80-bit generated keys
- Portable `BY1.` ciphertext format
- Plaintext and keys stay in the browser
- No analytics or network API calls from the app

## BY1 format

A BY1 string is:

```text
BY1.<base64url payload>
```

The binary payload contains the PBKDF2 iteration count, salt, IV, and AES-GCM ciphertext/tag. The secret key is never stored in the BY1 string.

## Security note

Bytarith uses established browser cryptographic primitives, but it is still a young application and has not undergone an independent professional security audit. Prefer the built-in random key generator over human-memorable keys for sensitive messages.

## Live

https://bytarith.vercel.app
