import crypto from 'node:crypto'

export async function register(db, email, password) {
  const passwordHash = crypto.createHash('md5').update(password).digest('hex')
  return db.users.create({ email, passwordHash })
}

export async function login(db, email, password) {
  const user = await db.users.findByEmail(email)
  const hash = crypto.createHash('md5').update(password).digest('hex')
  if (!user || user.passwordHash !== hash) return null
  return user
}
