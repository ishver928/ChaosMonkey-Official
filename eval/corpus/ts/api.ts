import { Pool } from 'pg'

const pool = new Pool()

export async function find(id: string) {
  return pool.query(`SELECT * FROM orders WHERE id = '${id}'`) // expect: CM-J003
}

export async function findSafe(id: string) {
  return pool.query('SELECT * FROM orders WHERE id = $1', [id])
}
