# DisCrypt
The idea is just to talk via discord in an secure way (mostly in dm for  now)

You first add a peer (with the channel id of the dm with him), then you can freely chat with him, without anyone else, knowing what your conversation is about.

It's a step further in security, to make discord a safer place, and to prevent, even if you're acconut get compromised, your message to get compromised too.

Draw back:
- if your computer get compromised, the attacker can get your private key (and the public key of the peer) and decrypt all the message.
- there's no safe keysharing feature for now, so be carefull the way you exchange them, a mitm attack can be performed, if you exchange your key over an unsafe channel.
- for now there's no forward secrecy (I'll add it soon)

I'm using nacl box method, meaning X25519 ECDH + XSalsa20-Poly1305.

TODO:
- edit message function
- reply message function
- file encryption / decryption
- rewrite for easier understanding
- edit the gui so its easier to add user
- forward secrecy (exchange new keypair every n message)
- prevent xss / any dom vulnerability
- patch bugs
- import / export keys + secure the keys with a password.
