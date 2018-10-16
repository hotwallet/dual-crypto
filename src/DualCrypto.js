import 'babel-polyfill'
import { ec as EC } from 'elliptic'

// TODO: consider https://github.com/bitchan/eccrypto
const ec = new EC('secp256k1')

function stringToArrayBuffer(string) {
  return new window.TextEncoder('utf-8').encode(string)
}

const bufToStr = str => (new TextDecoder().decode(str))

function toHex(str) {
  return unescape(encodeURIComponent(str))
    .split('')
    .map(v => v.charCodeAt(0).toString(16))
    .join('')
}

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

const generateMasterKey = async (password) => {
  return window.crypto.subtle.importKey(
    'raw',
    stringToArrayBuffer(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey', 'deriveBits']
  )
}

const generateSymmetricKey = async (masterKey, salt, iterations) => {
  return await window.crypto.subtle.deriveKey(
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

const generateAsymmetricKeyPair = async (masterKey, salt, iterations) => {
  let entropy = await window.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: stringToArrayBuffer(salt),
      iterations,
      hash: 'SHA-256'
    },
    masterKey,
    256
  )
  entropy = new Uint8Array(entropy)
  return ec.genKeyPair({entropy})
}

const DualCrypto = async ({ secret, salt, iterations = 1000000 } = {}) => {
  if (!secret) throw new Error('secret is required')

  // if we assume no two users have the same secret, then we can derive a default unique salt
  // otherwise, a unique salt should be provided
  salt = salt || secret
  const saltReverse = salt.split('').reverse().join('')
  const symmetricSalt = crypto.subtle.digest('SHA-256', stringToArrayBuffer(salt))
  const asymmetricSalt = crypto.subtle.digest('SHA-256', stringToArrayBuffer(saltReverse))

  const masterKey = await generateMasterKey(secret)
  const symmetric = await generateSymmetricKey(masterKey, symmetricSalt, iterations)
  const asymmetric = await generateAsymmetricKeyPair(masterKey, asymmetricSalt, iterations)

  const symmetricAlgo = 'AES-GCM'

  return {
    getPublicKey() {
      return asymmetric.getPublic().encode('hex')
    },

    sign(message) {
      // TODO: hash the message to sign
      return asymmetric.sign(toHex(message)).toDER('hex')
    },

    encrypt(message) {
      const data = stringToArrayBuffer(message)
      const iv = window.crypto.getRandomValues(new Uint8Array(16))
      return window.crypto.subtle.encrypt({ name: symmetricAlgo, iv }, symmetric, data)
        .then(encryptedData => {
          return arrayBufferToHexString(iv) + arrayBufferToHexString(encryptedData)
        })
    },

    decrypt(encryptedMessage) {
      const iv = hexToBuf(encryptedMessage.substring(0, 32))
      const data = hexToBuf(encryptedMessage.substring(32))
      return window.crypto.subtle.decrypt({ name: symmetricAlgo, iv }, symmetric, data)
        .then(decryptedData => bufToStr(decryptedData))
    }
  }
}

export default DualCrypto

DualCrypto.verify = function ({ publicKey, message, signature } = {}) {
  const key = ec.keyFromPublic(publicKey, 'hex')
  // TODO: verify the hashed message that was signed
  return key.verify(toHex(message), signature)
}

if (typeof window !== 'undefined') {
  window.DualCrypto = DualCrypto
}