import 'regenerator-runtime/runtime'
import { ec as EC } from 'elliptic'

const ec = new EC('secp256k1')

function stringToArrayBuffer(string) {
  return new window.TextEncoder('utf-8').encode(string)
}

const crypto = window.crypto

const bufToStr = str => (new TextDecoder().decode(str))

function hexToBuf(hex) {
  const bytes = []
  for (let c = 0; c < hex.length; c += 2) {
    bytes.push(parseInt(hex.substr(c, 2), 16))
  }
  return new Uint8Array(bytes)
}

function arrayBufferToHexString(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer)
  var hexString = ''
  var nextHexByte
  for (var i = 0; i < byteArray.byteLength; i++) {
    nextHexByte = byteArray[i].toString(16)
    if (nextHexByte.length < 2) {
      nextHexByte = '0' + nextHexByte
    }
    hexString += nextHexByte
  }
  return hexString
}

const generateMasterKey = (password) => {
  return crypto.subtle.importKey(
    'raw',
    stringToArrayBuffer(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey', 'deriveBits']
  )
}

const generateSymmetricKey = (masterKey, salt, iterations) => {
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: stringToArrayBuffer(salt),
      iterations,
      hash: 'SHA-256'
    },
    masterKey,
    { name: 'AES-GCM', 'length': 128 },
    true,
    ['encrypt', 'decrypt']
  )
}

const generateAsymmetricKeyPair = (masterKey, salt, iterations) => {
  return crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: stringToArrayBuffer(salt),
      iterations,
      hash: 'SHA-256'
    },
    masterKey,
    256
  ).then(bits => {
    const entropy = new Uint8Array(bits)
    return ec.genKeyPair({entropy})
  })

}

const sha256 = str => {
  return crypto.subtle.digest('SHA-256', stringToArrayBuffer(str))
    .then(arrayBuffer => arrayBufferToHexString(arrayBuffer))
}

const DualCrypto = ({ secret, salt, iterations = 1000000 } = {}) => {
  if (!secret) throw new Error('secret is required')

  // if we assume no two users have the same secret, then we can derive a default unique salt
  // otherwise, a unique salt should be provided
  salt = salt || secret
  const saltReverse = salt.split('').reverse().join('')
  const symmetricAlgo = 'AES-GCM'
  return generateMasterKey(secret)
    .then(masterKey => {
      return Promise.all([
        generateSymmetricKey(masterKey, sha256(salt), iterations),
        generateAsymmetricKeyPair(masterKey, sha256(saltReverse), iterations)
      ])
    })
    .then(([symmetric, asymmetric]) => {
      return {
        getPublicKey() {
          return asymmetric.getPublic().encode('hex')
        },

        sign: async message => {
          const hash = await sha256(message)
          return asymmetric.sign(hash).toDER('hex')
        },

        encrypt: async message => {
          const data = stringToArrayBuffer(message)
          const iv = window.crypto.getRandomValues(new Uint8Array(16))
          const encryptedData = await crypto.subtle.encrypt({
            name: symmetricAlgo,
            iv
          }, symmetric, data)
          return arrayBufferToHexString(iv) + arrayBufferToHexString(encryptedData)
        },

        decrypt: async encryptedMessage => {
          const iv = hexToBuf(encryptedMessage.substring(0, 32))
          const data = hexToBuf(encryptedMessage.substring(32))
          const decryptedData = await crypto.subtle.decrypt({
            name: symmetricAlgo,
            iv
          }, symmetric, data)
          return bufToStr(decryptedData)
        }
      }
    })
}

DualCrypto.verify = function ({ publicKey, message, signature } = {}) {
  const key = ec.keyFromPublic(publicKey, 'hex')
  return sha256(message)
    .then(hash => key.verify(hash, signature))
}

export default DualCrypto

if (typeof window !== 'undefined') {
  window.DualCrypto = DualCrypto
}