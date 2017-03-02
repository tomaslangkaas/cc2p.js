var cc2p = (function() {
  function toLE(i) {
    for (var j = Math.floor(i / 0x1000000),
        x = 0, a = []; x < 4; x++) {
      a[x] = (i >>> (x * 8)) & 0xff;
      a[x + 4] = (j >>> (x * 8)) & 0xff;
    }
    return a;
  }
  
  function compare(a, b) {//constant time
        if (a.length !== b.length) return false;
        for (var i = 0, r = 0; i < a.length; i++) {
            r |= a[i] ^ b[i];
        }
        return !(r ^ 0);
    }

  function cc20p1305(key) {
    return function(nonce, msg, aad, tag) {
      aad = aad || [];
      //poly1305 setup
      var r = [],
        h = [],
        c = [];
      var k = chacha20(key, nonce, 0, Array(32));
      var out = [];
      var len1 = aad.length,
        len2 = msg.length;
      setup(k, r, h, c);

      //if encryption, start with encrypting msg
      if (!tag) {
        chacha20(key, nonce, 1, msg);
      }
      update(r, h, c, aad, 0, len1 + (16 - len1 % 16) % 16);
      update(r, h, c, msg, 0, len2 + (16 - len2 % 16) % 16);
      update(r, h, c, toLE(len1).concat(toLE(len2)), 0, 16);
      finish(k, h, c, out);
      if (tag) { //if decryption
        //todo: constant-time comparison
        if (compare(out, tag)) {
          return chacha20(key, nonce, 1, msg);
        } else {
          return false;
        }
      } else {
        return [msg, out];
      }
    }
  }

  //https://tools.ietf.org/html/rfc7539

  //chacha20(key, nonce, counter, plaintext) => mutates plaintext, returns plaintext
  //key       = array of 32 octets (256 bits)
  //nonce     = array of 12 octets (96 bits)
  //counter   = integer
  //plaintext = array of message octets

  function readWord(arr1, index1, arr2, index2) {
    //read 4 bytes from arr1, write as 32-bit word 
    //to arr2 in little-endian order
    arr2[index2] = arr1[index1] ^
      arr1[index1 + 1] << 8 ^
      arr1[index1 + 2] << 16 ^
      arr1[index1 + 3] << 24;
  }

  function qr(arr, a, b, c, d) {
    //quarterround function applied to indices a to d in arr
    arr[b] = (arr[b] ^= (arr[c] += (arr[d] = (arr[d] ^= (arr[a] += arr[b])) << 16 ^ arr[d] >>> 16))) << 12 ^ arr[b] >>> 20;
    arr[b] = (arr[b] ^= (arr[c] += (arr[d] = (arr[d] ^= (arr[a] += arr[b])) << 8 ^ arr[d] >>> 24))) << 7 ^ arr[b] >>> 25;
  }
  //chacha20 function, expects:
  // 256-bit key as array of bytes (numbers in range 0-255),
  // 96-bit nonce as array of bytes,
  // initial counter as 32-bit integer,
  // plaintext as array of bytes
  //the function mutates plaintext array 
  //(XORs keystream into it to create ciphertext),
  //and returns the mutated array
  function chacha20(key, nonce, counter, plaintext) {
    var state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574],
      workingState,
      len = plaintext.length,
      pos, i, j, copylen, temp;
    //copy key and nonce to state, little-endian
    for (i = 0; i < 4; i++) {
      readWord(key, i * 4, state, i + 4);
      readWord(key, (i + 4) * 4, state, i + 8);
      readWord(nonce, i * 4, state, ((i + 1) & 3) + 12);
    }
    //process blocks
    for (pos = 0; pos < len;) {
      //update counter
      state[12] = counter++;
      //copy state to workingState
      workingState = state.slice();
      //20 rounds of innerBlock
      for (i = 0; i < 10; i++) {
        qr(workingState, 0, 4, 8, 12);
        qr(workingState, 1, 5, 9, 13);
        qr(workingState, 2, 6, 10, 14);
        qr(workingState, 3, 7, 11, 15);
        qr(workingState, 0, 5, 10, 15);
        qr(workingState, 1, 6, 11, 12);
        qr(workingState, 2, 7, 8, 13);
        qr(workingState, 3, 4, 9, 14);
      }
      //compute number of bytes to output
      copylen = pos + 64;
      if (copylen > len) copylen = len;
      //add workingState to state and XOR into
      //plaintext in little-endian order
      for (i = 0; pos < copylen; pos++) {
        j = pos & 3;
        if (!j) {
          temp = (state[i] + workingState[i++]) | 0;
        }
        plaintext[pos] ^= (temp >>> (8 * j)) & 0xff;
      }
    }
    //return mutated plaintext array (now ciphertext)
    return plaintext;
  }  

  /*
  poly1305
  20080912
  D. J. Bernstein
  Public domain.
  Adapted from source at https://github.com/floodyberry/supercop/blob/master/crypto_onetimeauth/poly1305/ref/auth.c
  */

  function add(h, c) {
    var j, u = 0;
    for (j = 0; j < 17; ++j) {
      u += h[j] + c[j];
      h[j] = u & 255;
      u >>= 8;
    }
  }

  function squeeze(h) {
    var j, u = 0;
    for (j = 0; j < 16; ++j) {
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }
    u += h[16];
    h[16] = u & 3;
    u = 5 * (u >> 2);
    for (j = 0; j < 16; ++j) {
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }
    u += h[16];
    h[16] = u;
  }

  var minusp = [
    5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
  ];

  function freeze(h) {
    var j, negative, horig = [];
    for (j = 0; j < 17; ++j) horig[j] = h[j];
    add(h, minusp);
    negative = -(h[16] >> 7);
    for (j = 0; j < 17; ++j) h[j] ^= negative & (horig[j] ^ h[j]);
  }

  function mulmod(h, r) {
    var i, j, u, hr = [];
    for (i = 0; i < 17; ++i) {
      u = 0;
      for (j = 0; j <= i; ++j) u += h[j] * r[i - j];
      for (j = i + 1; j < 17; ++j) u += 320 * h[j] * r[i + 17 - j];
      hr[i] = u;
    }
    for (i = 0; i < 17; ++i) h[i] = hr[i];
    squeeze(h);
  }

  function finish(k, h, c, out) {
    freeze(h);
    for (var j = 0; j < 16; ++j) c[j] = k[j + 16];
    c[16] = 0;
    add(h, c);
    for (j = 0; j < 16; ++j) out[j] = h[j];
  }

  function update(r, h, c, inp, position, lastpos) {
    var j, i;
    for (; position < lastpos; position += 16) {
      for (j = 0; j < 17; ++j) c[j] = 0;
      for (j = 0, i = position;
        (j < 16) && (i < lastpos); j++, i++) c[j] = inp[i] || 0;
      c[j] = 1;
      add(h, c);
      mulmod(h, r);
    }
  }

  function setup(k, r, h, c) {
    for (var j = 0; j < 16; j++) {
      r[j] = k[j];
      h[j] = 0;
    }
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
    r[16] = h[16] = 0;
  }

  cc20p1305['poly1305'] = function(key, msg) {
    var r = [],
      h = [],
      c = [],
      out = [];
    setup(key, r, h, c);
    update(r, h, c, msg, 0, msg.length);
    finish(key, h, c, out);
    return out;
  }

  cc20p1305['chacha20'] = chacha20;
  return cc20p1305;
})();
