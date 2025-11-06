# DisCrypt - End-to-End Encryption for Discord

Secure peer-to-peer messaging on Discord using client-side encryption. Messages and files remain encrypted end-to-end, even if your Discord account is compromised.

## How It Works

1. Add a peer by their Channel ID (DM channel) and public keys
2. Messages auto-encrypt on send, auto-decrypt on receive, message edition is well handled
3. Only you and the intended recipient can read your messages
4. Encryption verified with color coding (blue = sent, green = received)

## Features

- End-to-end encryption using X25519 ECDH + XSalsa20-Poly1305 (TweetNaCl)
- Automatic message encryption/decryption
- Encrypted file attachments with Ed25519 signature verification
- Message editing support
- Reply handling for encrypted messages
- Peer management UI with key storage
- Works in DMs and group channels

## Security Model

**Threat Model**: Protects against message interception if your account is compromised.

**Does NOT protect against**:
- Private key compromise (if your computer is compromised)
- Man-in-the-middle attacks during key exchange (manually exchange keys via secure channel)
- Message metadata (timestamps, message count, presence)

**Implementation Details**:
- Private keys stored in browser localStorage only
- Uses NaCl.box (X25519 ECDH) for asymmetric encryption
- Ed25519 signatures for file authenticity verification
- Sender/recipient public keys included in message format for verification

## Limitations

- No forward secrecy (compromise of keypair compromises all messages)
- No built-in key exchange protocol (manual key sharing required)
- Private keys stored in plaintext in localStorage
- File upload MIME type spoofing (`.png` wrapper) for CORS bypass

## TODO

- [x] GUI improvements
- [x] Message editing
- [x] File encryption/decryption
- [x] Reply handling
- [ ] Message authenticity verification (sender signature)
- [ ] Forward secrecy (keypair rotation)
- [ ] Key import/export with password protection
- [ ] Code refactor for maintainability
- [ ] Link preview support
- [ ] Better media handling after decryption