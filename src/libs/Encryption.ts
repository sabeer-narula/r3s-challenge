import crypto from 'crypto'

export default function Encryption(secret: string) {
  const alg = 'aes-256-ctr'

  return {
    _algorithm: alg,
    _secret: secret,

    encrypt(input: Buffer | string) {
      const secret = getFilledSecret(this._secret)
      const { iv, key } = getKeyAndIV(secret)
      const cipher = crypto.createCipheriv(this._algorithm, key, iv)

      const inputStr =
        input instanceof Buffer ? input.toString('base64') : input
      let cipherText = cipher.update(inputStr, 'utf8', 'base64')
      cipherText += cipher.final('base64')
      return `${cipherText}:${iv.toString('base64')}`
    },

    // decrypts cipher text using the aes-256-ctr algorithm
    decrypt(ciphertext: string) {

      // splits ciphertext into the encrypted text and the initialization vector
      const [encryptedText, ivBase64] = ciphertext.split(':')
      const secret = getFilledSecret(this._secret)
      const iv = Buffer.from(ivBase64, 'base64') // converts IV back to buffer
      const { key } = getKeyAndIV(secret, iv)

      // creates a decipher object using the algorithm, derived key, and IV
      const decipher = crypto.createDecipheriv(this._algorithm, key, iv)
      let decrypted = decipher.update(encryptedText, 'base64', 'utf8') // converts b64 to utf8 while decrypting
      decrypted += decipher.final('utf8')
      return decrypted
    },
  }
}

// Private methods
function getFilledSecret(secret: string): string {
  const sha256Sum = crypto.createHash('sha256')
  sha256Sum.update(secret)
  return sha256Sum.digest('base64')
}

function getKeyAndIV(key: string, iv?: Buffer) {
  const ivBuffer = iv || crypto.randomBytes(16)
  const derivedKey = crypto.pbkdf2Sync(key, ivBuffer, 1e5, 32, 'sha256')
  return {
    iv: ivBuffer,
    key: derivedKey,
  }
}
