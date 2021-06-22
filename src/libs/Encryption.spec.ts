import assert from 'assert'
import Encryption from './Encryption'

describe('Encryption', function () {
  const enc = Encryption('abc123')
  const originalText = 'test123'
  let cipherTextAndIv: string
  let plainText: string

  describe('#encrypt()', function () {
    it(`should encrypt string without issue`, function () {
      cipherTextAndIv = enc.encrypt(originalText)
      assert.strictEqual(typeof cipherTextAndIv, 'string')
      assert.strictEqual(2, cipherTextAndIv.split(':').length)
    })
  })

  describe('#decrypt()', function () {
    it(`should decrypt cipher string without issue`, function () {
      plainText = enc.decrypt(cipherTextAndIv)
      assert.strictEqual(typeof plainText, 'string')
      assert.strictEqual(plainText, originalText)
    })
  })
})
