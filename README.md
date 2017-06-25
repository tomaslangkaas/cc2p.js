# cc2p.js
minimal JavaScript implementation of chacha20-poly1305

```javascript
var ciphertextAndTag = cc2p(key)(nonce, plaintext, aad);
//ciphertextAndTag is an array of [ciphertext, tag]
//where ciphertext is an array of octets and tag is an array of octets
//NOTE: plaintext array is mutated in place (to ciphertext)

var plaintext = cc2p(key)(nonce, ciphertext, aad, tag);
//plaintext is either false (if tag failed) or an array of octets
//NOTE: ciphertext array is mutated in place (to plaintext)
```

Pure JavaScript (ES3) implementation of [RFC7539](https://tools.ietf.org/html/rfc7539). The function `cc2p` takes a 256-bit key as an array of 32 octets and returns an encryption/decryption function. The encryption/decryption function takes a 96-bit nonce as an array of 12 octets, and an (optional) array of octets with associated data. To decrypt, also provide the 128-bit tag (MAC) as an array of 16 octets.

The encryption function returns `[ciphertext, tag]`, where both `ciphertext` and `tag` are arrays of octets.

The decryption function returns either `false`, if decryption fails (wrong tag), or the plaintext as an array of octets.

The function `cc2p` also provide access to the `cc2p.chacha20(key, nonce, counter, message)` primitive and the `cc2p.poly1305(key, message)` primitive. Please note that the `message` argument of `cc2p.chacha20(key, nonce, counter, message)` is mutated, make a copy if required to keep the original data.

Test vectors and tests are found in `index.html`. Test against [test vectors here](https://tomaslangkaas.github.io/cc2p.js/).
