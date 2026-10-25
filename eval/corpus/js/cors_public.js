const cors = require('cors')
const express = require('express')

const app = express()
app.use(cors()) // expect: CM-C004

app.use('/admin', cors({ origin: ['https://admin.example.com'] }))

module.exports = app
