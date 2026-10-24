const crypto = require('crypto')

function vulnCreateCipher(passphrase, text) {
  const c = crypto.createCipher('aes-256-cbc', passphrase) // expect: CM-C001
  return c.update(text, 'utf8', 'hex') + c.final('hex')
}

function vulnDes(key, iv, text) {
  return crypto.createCipheriv('des-ede3-cbc', key, iv).update(text) // expect: CM-C001
}

function vulnToken() {
  const resetToken = Math.random().toString(36).slice(2) // expect: CM-C002
  return resetToken
}

function safeGcm(key, text) {
  const iv = crypto.randomBytes(12)
  return crypto.createCipheriv('aes-256-gcm', key, iv).update(text)
}

function safeJitter() {
  return Math.floor(Math.random() * 1000)
}

function safeToken() {
  return crypto.randomBytes(32).toString('hex')
}

module.exports = { vulnCreateCipher, vulnDes, vulnToken, safeGcm, safeJitter, safeToken }
