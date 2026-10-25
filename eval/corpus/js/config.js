const express = require('express')
const cors = require('cors')
const https = require('https')

const app = express()
app.use(cors({ origin: '*', credentials: true })) // expect: CM-J004

const agent = new https.Agent({ rejectUnauthorized: false }) // expect: CM-D007
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0' // expect: CM-D007

module.exports = { app, agent }
