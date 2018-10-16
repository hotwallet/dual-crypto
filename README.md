# dual-crypto

Simple symmetric and asymmetric cryptography for the browser

### Install

```
npm i dual-crypto
```

### Usage

```js
import DualCrypto from 'dual-crypto'

async () => {
  const secret = 'correct horse battery staple'
  const salt = 'my custom salt' // (optional) if secret is not unique, use a custom salt
  const dc = await DualCrypto({ secret, salt })
  const message = 'I am Satoshi Nakamoto'

  // asymmetric functions
  const publicKey = dc.getPublicKey()
  const signature = dc.sign(message)
  const isAuthentic = DualCrypto.verify({ publicKey, message, signature })

  // symmetric functions
  const encryptedMessage = await dc.encrypt(message)
  const decryptedMessage = await dc.decrypt(encryptedMessage)
}
```

### License

MIT