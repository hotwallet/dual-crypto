const DualCrypto = window.DualCrypto

const secret = 'correct horse battery staple'
console.log('secret:', secret)

DualCrypto({ secret })
  .then(dc => {
    const message = 'Satoshi Nakamoto'

    // asymmetric functions
    const publicKey = dc.getPublicKey()
    console.log('publicKey:', publicKey)

    dc.sign(message).then(signature => {
      console.log('signature:', signature)

      DualCrypto.verify({ publicKey, message, signature }).then(isAuthentic => {
        console.log(message, isAuthentic)
      })

      const wrongMessage = 'Craig Wright'
      DualCrypto.verify({ publicKey, message: wrongMessage, signature }).then(result => {
        console.log(wrongMessage, result)
      })
    })

    // // symmetric functions
    dc.encrypt(message).then(encryptedMessage => {
      console.log('encryptedMessage:', encryptedMessage)
      dc.decrypt(encryptedMessage).then(decryptedMessage => {
        console.log('decryptedMessage:', decryptedMessage)
      })
    })
  })
