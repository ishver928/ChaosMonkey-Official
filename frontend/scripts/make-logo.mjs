// Crops the circular CalHacks 13.0 badge out of logo-source.png and writes the app's logo assets.
// Usage: node scripts/make-logo.mjs   (reads ./logo-source.png, never modifies it)
import sharp from 'sharp'
import fs from 'node:fs'

const SRC = 'logo-source.png'
const { data, info } = await sharp(SRC).ensureAlpha().raw().toBuffer({ resolveWithObject: true })
const { width, height } = info

// Find the bounding box of everything that isn't near-white: that's the badge.
let minX = width, minY = height, maxX = 0, maxY = 0
for (let y = 0; y < height; y++) {
  for (let x = 0; x < width; x++) {
    const i = (y * width + x) * 4
    const r = data[i], g = data[i + 1], b = data[i + 2]
    if (data[i + 3] > 24 && Math.min(r, g, b) < 235) {
      if (x < minX) minX = x
      if (x > maxX) maxX = x
      if (y < minY) minY = y
      if (y > maxY) maxY = y
    }
  }
}
const cx = (minX + maxX + 1) / 2
const cy = (minY + maxY + 1) / 2
const radius = Math.max(maxX - minX + 1, maxY - minY + 1) / 2
console.log(`badge bbox x ${minX}-${maxX}, y ${minY}-${maxY}; center (${cx}, ${cy}), r ${radius}`)

// Square crop with a 1px safety margin, then a circular alpha mask with a soft 1.5px edge.
const size = Math.ceil(radius * 2) + 2
const left = Math.round(cx - size / 2)
const top = Math.round(cy - size / 2)
const crop = Buffer.alloc(size * size * 4)
for (let y = 0; y < size; y++) {
  for (let x = 0; x < size; x++) {
    const sx = left + x, sy = top + y
    const o = (y * size + x) * 4
    if (sx < 0 || sy < 0 || sx >= width || sy >= height) continue
    const i = (sy * width + sx) * 4
    const d = Math.hypot(sx + 0.5 - cx, sy + 0.5 - cy)
    const alpha = Math.max(0, Math.min(1, (radius - d) / 1.5 + 0.5))
    crop[o] = data[i]; crop[o + 1] = data[i + 1]; crop[o + 2] = data[i + 2]
    crop[o + 3] = Math.round(data[i + 3] * alpha)
  }
}
const base = sharp(crop, { raw: { width: size, height: size, channels: 4 } }).png()
const master = await base.toBuffer()

const out = async (file, px) => {
  await sharp(master).resize(px, px, { kernel: 'lanczos3' }).png({ compressionLevel: 9 }).toFile(file)
  console.log(`wrote ${file} (${px}x${px})`)
}
fs.mkdirSync('public/assets', { recursive: true })
await out('public/logo.png', 512)
await out('public/favicon.png', 64)
await out('public/apple-touch-icon.png', 180)
// Same filename and 1254x1254 dimensions as the reference project's mascot, so anything pointing at it keeps working.
await out('public/assets/chaosmonkey-mascot.png', 1254)

// favicon.ico with embedded PNGs (16, 32, 48).
const sizes = [16, 32, 48]
const pngs = await Promise.all(sizes.map((s) => sharp(master).resize(s, s).png().toBuffer()))
const header = Buffer.alloc(6 + 16 * sizes.length)
header.writeUInt16LE(0, 0); header.writeUInt16LE(1, 2); header.writeUInt16LE(sizes.length, 4)
let offset = header.length
sizes.forEach((s, n) => {
  const e = 6 + n * 16
  header.writeUInt8(s, e); header.writeUInt8(s, e + 1); header.writeUInt8(0, e + 2); header.writeUInt8(0, e + 3)
  header.writeUInt16LE(1, e + 4); header.writeUInt16LE(32, e + 6)
  header.writeUInt32LE(pngs[n].length, e + 8); header.writeUInt32LE(offset, e + 12)
  offset += pngs[n].length
})
fs.writeFileSync('public/favicon.ico', Buffer.concat([header, ...pngs]))
console.log('wrote public/favicon.ico (16/32/48)')
