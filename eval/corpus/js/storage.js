const jwt = require('jsonwebtoken')

function saveSession(token, user) {
  localStorage.setItem('authToken', token) // expect: CM-D001
  sessionStorage.setItem('profile', JSON.stringify(user)) // expect: CM-D001
  localStorage.setItem('data', JSON.stringify({ email: user.email, dob: user.dob })) // expect: CM-D001
}

function prefs(theme) {
  localStorage.setItem('theme', theme)
  localStorage.setItem('userPrefersDark', 'true') // fp-fixed: not user data
}

function sign(id) {
  return jwt.sign({ sub: id }, 'keyboard-cat-secret') // expect: CM-D004
}

function readToken(token) {
  return jwt.decode(token) // expect: CM-J005
}

function login(res, sid) {
  res.cookie('sid', sid) // expect: CM-D005
  res.cookie('sid2', sid, { httpOnly: true, secure: true, sameSite: 'lax' })
}

function verified(token) {
  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] })
}

module.exports = { saveSession, prefs, sign, readToken, login, verified }
