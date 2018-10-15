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
  const secret = DualCrypto.generateSecret(6)
  const dc = await DualCrypto({ secret })
  const message = 'I am Satoshi Nakamoto'

  // asymmetric functions
  const publicKey = dc.getPublicKey()
  const signature = dc.sign(message)
  const isAuthentic = DualCrypto.verify({ publicKey, message, signature })

  // symmetric functions
  dc.encrypt(message).then(encryptedMessage => {
    dc.decrypt(encryptedMessage).then(decryptedMessage => {
      // message === decryptedMessage
    })
  })

}
```

### License

MIT