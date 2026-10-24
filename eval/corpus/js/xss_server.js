const express = require('express')

const app = express()

app.get('/hello', (req, res) => {
  res.send(`<h1>Hello ${req.query.name}</h1>`) // expect: CM-J006
})

app.get('/search', (req, res) => {
  const q = req.query.q
  res.send('<p>Results for ' + q + '</p>') // expect: CM-J006
})

app.get('/echo', (req, res) => {
  res.send(req.query.msg) // expect: CM-J006
})

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => '&#' + c.charCodeAt(0) + ';')

app.get('/hello-safe', (req, res) => {
  res.send(`<h1>Hello ${escapeHtml(req.query.name)}</h1>`)
})

app.get('/api/item', (req, res) => {
  res.json({ id: req.params.id })
})

app.get('/count', (req, res) => {
  res.send(`<p>${Number(req.query.n) || 0} items</p>`)
})

app.get('/static', (req, res) => {
  res.send('<p>ok</p>')
})
