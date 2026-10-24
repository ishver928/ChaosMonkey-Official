const mongoose = require('mongoose')

function logUser(user) {
  console.log('login', user) // expect: CM-P006
}

function lookup(email) {
  return fetch(`/api/lookup?email=${email}`) // expect: CM-P007
}

function logSafe(id) {
  console.log('login id', id)
}

const PatientSchema = new mongoose.Schema({
  ssn: String, // expect: CM-P008
  dob: { type: Date }, // expect: CM-P008
  ssnHash: String,
})

module.exports = { logUser, lookup, logSafe, PatientSchema }
