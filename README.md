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
  const message = 'I am Satoshi Nakamoto'

async () => {
  const dc = await DualCrypto({ secret, salt })

  // asymmetric functions
  const publicKey = dc.getPublicKey()
  const signature = await dc.sign(message)
  const isAuthentic = await DualCrypto.verify({ publicKey, message, signature })

  // symmetric functions
  const encryptedMessage = await dc.encrypt(message)
  const decryptedMessage = await dc.decrypt(encryptedMessage)
  
  console.log({ publicKey, signature, isAuthentic, encryptedMessage, decryptedMessage })
}
```
*Note: if your secret is guessable, specify a `salt` to prevent [rainbow table attacks](https://en.wikipedia.org/wiki/Rainbow_table).

Output:
```
{ 
  publicKey: '04ee98503cf989465960b4aad8223b835c43c66fc37cddae9e4d25f7961dbb3dad6c2286a579232a3f9b0024a8a23a8a103882dd424e5f74db8b8f93ae47766f9b',
  signature: '304402207ded55332c8399ae093341793aebb76bdafa32776babb16c9a26239ff989eebb022037ce3cc484a6f9a668f38c59dd21894aba7661eeb555bc9cd5525dc40c35e536',
  isAuthentic: true,
  encryptedMessage: '9ddc3d6d1b1436334b54c223e0f6c7407e0265c38d9585ca10a9d221f3215f042152b87e505c97ffcdb712b493ff01fd5b5ba40544',
  decryptedMessage: 'I am Satoshi Nakamoto'
}
```

### License

MIT
