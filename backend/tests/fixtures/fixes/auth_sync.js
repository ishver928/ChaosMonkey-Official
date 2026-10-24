const crypto = require('crypto')

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex')
}

function checkPassword(password, stored) {
  return crypto.createHash('sha1').update(password).digest('hex') === stored
}

module.exports = { hashPassword, checkPassword }
