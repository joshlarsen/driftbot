/**
 * Event handlers for Puppeteer page/client events.
 */

const fs = require('fs')
const esprima = require('esprima')
const logger = require('./logger')
const issues = require('./issues')

let results = {
  script_hosts: [],
  xhr_hosts: [],
  websocket_hosts: [],
  webworker_hosts: [],
  obfuscated_script_hosts: [],
  suspicious_script_hosts: []
}

/**
 * .response() - General response handler
 * @param {puppeteer.response} res
 */
function response(res) {
  const req = res.request()
  const ref = req.headers().referer || ''
  const url = req.url()
  const uri = new URL(url)
  const hostname = uri.host
  const pathname = uri.pathname
  const type = req.resourceType()

  if (['script', 'xhr'].includes(type)) {
    logger.log(`[${type}] url=${url} referrer=${ref}`)
  }

  if (type === 'script') {
    _processScript(res, hostname, pathname)
  }

  if (type === 'xhr') {
    _processXHR(hostname)
  }
}

/**
 * .websocket() - Websocket handler
 * @param {puppeteer.request} data
 */
function websocket(data) {
  const url = data.url
  const uri = new URL(url)
  const hostname = uri.host

  logger.log(`[ws] ${hostname} (${url})`)

  if (results.websocket_hosts.indexOf(hostname) < 0) {
    results.websocket_hosts.push(hostname)
  }
}

/**
 * .worker() - WebWorker handler
 * @param {puppeteer.response} data
 */
function worker(data) {
  const url = data.url().startsWith('blob:') ? data.url().split('blob:')[1] : data.url()
  const uri = new URL(url)
  const hostname = uri.host

  logger.log(`[webworker] ${hostname} (${url})`)

  if (results.webworker_hosts.indexOf(hostname) < 0) {
    results.webworker_hosts.push(hostname)
  }
}

/**
 * .console_() - Console message handler
 * @param {puppeteer.consolemessage} msg
 */
function console_(msg) {
  const url = msg.location().url

  logger.log(`[console][${msg.type()}] message=${msg.text()} url=${url}`)
}

/**
 * .close() - Process the data we collected
 */
async function close() {
  const github = process.env.GITHUB_TOKEN
  const file = fs.existsSync('./authorized_hosts.json')

  if (!file) return

  const data = fs.readFileSync(file)
  const hosts = JSON.parse(data)
  const report = {}
  const baseline = Object.values(hosts).some(h => h.length > 0)

  // filter authorized hosts out of final report
  Object.keys(results).forEach(type => {
    if (hosts[type]) {
      // filter for hosts that are not authorized for this type
      report[type] = results[type].filter(t => !hosts[type].some(h => _match(h, t))).sort()
    } else {
      // no authorized hosts for this type
      report[type] = results[type].sort()
    }
  })

  console.log('\n-+-+-+-\n')
  logger.log('analysis complete')

  // handle GitHub issues
  await _handleIssues(report, github, baseline)

  // output recommendations for an initial baseline config
  if (!baseline) _recommendations(report, file)
}

/*
 *
 * Internal handler helpers
 *
 */

/**
 * Create, label, and close GitHub issues as needed
 * @param {object} report
 * @param {boolean} github
 * @param {boolean} baseline
 */
async function _handleIssues(report, github, baseline) {
  Object.keys(report).forEach(async type => {
    let title = type.replace(/_/g, ' ').replace('hosts', 'host')
    let label = type.replace(/_/g, '-')
    let issues_ = []

    report[type].forEach(host => {
      logger.warn(`${title}=${host}`)
    })

    /* only interact with Issues if we are running with 
     * GitHub credentials after setting a baseline config */
    if (github && baseline) {
      issues_ = await issues.list(label)
    }

    let count = report[type].length

    if (report[type] && count > 0) {
      let opts = {
        type: type,
        title: title,
        hosts: report[type],
        label: label
      }

      // unmark if previously resolved
      issues_.forEach(async issue => await issues.unmark(issue))

      // create issue for type
      if (github && baseline && issues_.length == 0) await issues.create(opts)

      logger.warn(`[${label}] ${count} unauthorized ${count == 1 ? 'host' : 'hosts'} observed`)

    } else {

      // close existing issues for type with 'resolved' label
      issues_.forEach(async issue => await issues.mark(issue))

      logger.log(`[${label}] no unauthorized hosts observed`)
    }
  })
}

/**
 * Process script response
 * @param {puppeteer.response} res
 * @param {string} host
 * @param {string} path
 */
function _processScript(res, host, path) {
  if (results.script_hosts.indexOf(host) < 0) {
    results.script_hosts.push(host)
  }

  // analyze JavaScript
  res
    .buffer()
    .then(buffer => {
      let content = buffer.toString()
      _detectSuspiciousCalls(content, host, path)
      _calculateObfuscationFactor(content, host, path)
    })
    .catch(err => {
      console.log(`[error][ast] ${err.message}`)
    })

}

/**
 * Process XHR response
 * @param {string} host
 */
function _processXHR(host) {
  if (results.xhr_hosts.indexOf(host) < 0) {
    results.xhr_hosts.push(host)
  }
}

/**
 * Walk AST for suspicious function calls
 * @param {string} source
 * @param {object} opts
 * @param {string} path
 */
function _detectSuspiciousCalls(source, host, path) {
  const opts = {
    tolerant: true
  }

  logger.log(`[ast] analyzing script path=${path}`)

  esprima.parseScript(source, opts, function(node) {
    if (_isSuspiciousCall(host, node, path)) {
      if (results.suspicious_script_hosts.indexOf(host) < 0) {
        results.suspicious_script_hosts.push(host)
      }
    }
  })
}

/**
 * Is the function call suspicious?
 * @param {string} host
 * @param {esprima.node} node
 * @param {string} path
 * @return {boolean}
 */
function _isSuspiciousCall(host, node, path) {
  const suspicious_calls = process.env.SUSPICIOUS_CALLS ? process.env.SUSPICIOUS_CALLS.split(',') : ['eval', 'atob', 'btoa']

  if (node.type == 'MemberExpression' && suspicious_calls.includes(node.property.name)) {

    logger.warn(`[ast] script from host=${host} path=${path} called suspicious function=${node.property.name}`)

    return true
  }
}

/**
 * Simple calculation of the amount of script content that is obfuscated
 * @param {string} content
 * @param {string} host
 * @param {string} path
 */
function _calculateObfuscationFactor(content, host, path) {
  const limit = process.env.OBFUSCATION_LIMIT_PERCENT || 25.0
  const total = content.length

  let obf = {
    unicode: -0.01,
    hex: -0.01,
    escaped: -0.01,
    packed: -0.01,
  }

  if (total > 0) {
    try {
      // unicode
      obf.unicode = _obf(content.match(/\\u0/g) || [], total / 2) // raw unicode string is 2 chars
      if (obf.unicode > limit) {
        logger.log(`[obf][unicode] obfuscated script loaded from host=${host} path=${path} obfuscation=${obf.unicode}`)
      }

      // hex encoded
      obf.hex = _obf(content.match(/\\x[0-9a-fA-F]{2}/g) || [], total / 4) // raw hex string is 4 chars
      if (obf.hex > limit) {
        logger.log(`[obf][hex] obfuscated script loaded from host=${host} path=${path} obfuscation=${obf.hex}`)
      }

      // escaped
      obf.escaped = _obf(content.match(/%/g) || [], total)
      if (obf.escaped > limit) {
        logger.log(`[obf][escaped] obfuscated script loaded from host=${host} path=${path} obfuscation=${obf.escaped}`)
      }

      // any of a number of general packers (e.g. http://dean.edwards.name/packer/)
      // p,a,c,k,e,r
      //  or
      // p,a,c,k,e,d
      obf.packed = _obf(content.includes('function(p,a,c,k,e') ? [1] : [])
      if (obf.packed > limit) {
        logger.log(`[obf][packed] obfuscated script loaded from host=${host} path=${path} obfuscation=${obf.packed}`)
      }

      // if any obfuscation is over limit, add to results
      if (Object.values(obf).some(el => el >= limit)) {
        if (results.obfuscated_script_hosts.indexOf(host) < 0) {
          results.obfuscated_script_hosts.push(host)
        }
      }
    } catch (err) {
      logger.warn(`[obf] host=${host} error=${err.message}`)
    }
  } else {
    logger.log(`[obf] host=${host} erorr=zero length script detected - possibly blocked by Cross-Origin Read Blocking`)
  }
}

/**
 * Output recommendations when there is no existing baseline set
 * @param {object} results
 * @param {string} file
 */
function _recommendations(results, file) {
  console.log(`\n-+-+-+- No baseline config found. Add the following to \`${file}\` to set the current baseline:\n`)
  console.log(JSON.stringify(results, null, 2))
}

/**
 * Format obfuscation percentage
 * @param {array} matches
 * @param {integer} total
 * @return {float}
 */
function _obf(matches, total) {
  return matches.length > 0 ? ((matches.length / total) * 100).toFixed(2) : 0
}

/**
 * Host string compare via regex
 * @param {string} pattern
 * @param {string} str
 * @return {boolean}
 */
function _match(pattern, str) {
  let wildcard = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&') // regexp escape
  const regex = new RegExp(`^${wildcard.replace(/\*/g,'.*').replace(/\?/g,'.')}$`, 'i')
  return regex.test(str)
}

module.exports = {
  response,
  console_,
  websocket,
  worker,
  close
}
