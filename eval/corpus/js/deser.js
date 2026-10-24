const serialize = require('node-serialize')

function vulnLoad(req) {
  return serialize.unserialize(req.cookies.profile) // expect: CM-J007
}

function safeLoad(raw) {
  return JSON.parse(raw)
}

module.exports = { vulnLoad, safeLoad }
