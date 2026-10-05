# Bytarith

**Bytarith** is a local-first short-key text encryption tool.

- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA-256 with 600,000 iterations
- Fresh 128-bit salt and 96-bit IV for every message
- Cryptographically random 80-bit generated keys
- Portable `BY1.` ciphertext format
- Plaintext and keys stay in the browser
- BT1 Transform mode with shortest-of-several reversible encoding strategies
- No analytics or network API calls from the app

## BY1 format

A BY1 string is:

```text
BY1.<base64url payload>
```

The binary payload contains the PBKDF2 iteration count, salt, IV, and AES-GCM ciphertext/tag. The secret key is never stored in the BY1 string.

## BT1 Transform

Transform mode lets you choose the exact visible text and generates a `BT1.` key that reconstructs the original message when paired with that visible text.

BT1 tries multiple local representations, including raw masking, prefix/suffix patches, sparse byte edits, Deflate compression, and compressed patches, then keeps the shortest result. BT1 is reversible encoding, not encryption; possession of both the visible text and transform key is enough to restore the original.

Encryption mode also accepts keys as short as two characters for experimentation, but short human-chosen keys are explicitly treated as weak and are vulnerable to offline guessing.

## Security note

Bytarith uses established browser cryptographic primitives, but it is still a young application and has not undergone an independent professional security audit. Prefer the built-in random key generator over human-memorable keys for sensitive messages.

## Live

https://bytarith.vercel.app
