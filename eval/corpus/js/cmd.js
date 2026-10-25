const { exec, execFile, spawn } = require('child_process')

function vulnTemplate(host) {
  exec(`ping -c 1 ${host}`) // expect: CM-J002
}

function vulnConcat(file) {
  exec('cat ' + file, () => {}) // expect: CM-J002
}

function vulnSpawnShell(name) {
  spawn(`tar -czf ${name}.tgz .`, { shell: true }) // expect: CM-J002
}

function safeExecFile(host) {
  execFile('ping', ['-c', '1', host])
}

function safeRegex(input) {
  // fp-fixed: RegExp.prototype.exec is not child_process.exec
  return /(\d+)-(\d+)/.exec(input + '')
}

function safeConstant() {
  exec('ls -la /var/log')
}

module.exports = { vulnTemplate, vulnConcat, vulnSpawnShell, safeExecFile, safeRegex, safeConstant }
