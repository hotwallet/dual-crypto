const DualCrypto = window.DualCrypto

const secret = DualCrypto.generateSecret(6)
console.log('secret:', secret)

DualCrypto({ secret })
  .then(dc => {
    const message = 'Satoshi Nakamoto'

    // asymmetric functions
    const publicKey = dc.getPublicKey()
    console.log('publicKey:', publicKey)

    const signature = dc.sign(message)
    console.log('signature:', signature)

    const isAuthentic = DualCrypto.verify({ publicKey, message, signature })
    console.log(message, isAuthentic)

    const wrongMessage = 'Craig Wright'
    const result = DualCrypto.verify({ publicKey, message: wrongMessage, signature })
    console.log(wrongMessage, result)

    // // symmetric functions
    dc.encrypt(message).then(encryptedMessage => {
      console.log('encryptedMessage:', encryptedMessage)
      dc.decrypt(encryptedMessage).then(decryptedMessage => {
        console.log('decryptedMessage:', decryptedMessage)
      })
    })
  })
