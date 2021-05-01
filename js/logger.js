/**
 * Generic logging wrapper
 */
function log(msg) {
  if (!process.env.DISABLE_LOGGING) {
    console.log(`[\x1b[38;5;39minfo\x1b[0m] ${msg}`)
  }
}

function warn(msg) {
  if (!process.env.DISABLE_LOGGING) {
    console.log(`[\x1b[38;5;166mwarn\x1b[0m] ${msg}`)
  }
}

module.exports = {
  log,
  warn
}
