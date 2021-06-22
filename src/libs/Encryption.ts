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

    decrypt(ciphertext: string) {
      // REDACTED, YOU SHOULD WRITE THE CODE TO DECRYPT THE CIPHERTEXT PROVIDED HERE
      return ''
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
