const { deserialize } = require('bson')

function decode(buf) {
  return deserialize(buf)
}

module.exports = { decode }
