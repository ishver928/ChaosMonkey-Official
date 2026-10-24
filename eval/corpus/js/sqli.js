const mysql = require('mysql2')
const TABLE = 'users'

function vulnTemplate(db, id) {
  return db.query(`SELECT * FROM users WHERE id = ${id}`) // expect: CM-J003
}

function vulnConcat(db, name) {
  return db.query("SELECT * FROM users WHERE name = '" + name + "'") // expect: CM-J003
}

function vulnBuilt(db, uid) {
  const sql = `DELETE FROM sessions WHERE user_id = '${uid}'`
  return db.execute(sql) // expect: CM-J003
}

function safeParams(db, id) {
  return db.query('SELECT * FROM users WHERE id = ?', [id])
}

function safeStaticTemplate(db) {
  // fp-fixed: a template literal with no interpolation is a constant query
  return db.query(`SELECT count(*) FROM users`)
}

function safeConstTable(db, id) {
  return db.query(`SELECT * FROM ${TABLE} WHERE id = ?`, [id])
}

function safeRoute(app) {
  app.get(`/items/${TABLE}`, (req, res) => res.json({ ok: true }))
}

module.exports = { mysql, vulnTemplate, vulnConcat, vulnBuilt, safeParams, safeStaticTemplate, safeConstTable, safeRoute }
