# dual-crypto

[![Build Status](https://travis-ci.org/hotwallet/dual-crypto.svg?branch=master)](https://travis-ci.org/hotwallet/dual-crypto)

Simple deterministic symmetric and asymmetric cryptography for the browser

### Install

```
npm i dual-crypto
```

### Usage

```js
import DualCrypto from 'dual-crypto'

  const secret = 'correct horse battery staple'
  const salt = 'my custom salt' // optional*

async () => {
  const dc = await DualCrypto({ secret, salt })
  const message = 'I am Satoshi Nakamoto'

  // asymmetric functions
  const publicKey = dc.getPublicKey()
  const signature = await dc.sign(message)
  const isAuthentic = await DualCrypto.verify({ publicKey, message, signature })

  // symmetric functions
  const encryptedMessage = await dc.encrypt(message)
  const decryptedMessage = await dc.decrypt(encryptedMessage)
}
```

*Note: if your secret is guessable, specify a `salt` to prevent [rainbow table attacks](https://en.wikipedia.org/wiki/Rainbow_table).

### License

MIT
