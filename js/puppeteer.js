const puppeteer = require('puppeteer-core')

/**
 * Wrap Puppeteer launcher
 */
function launch() {
  const browser = puppeteer.connect({
      browserWSEndpoint: 'ws://localhost:3333',
      defaultViewport: {
        width: 1920,
        height: 1080,
        deviceScaleFactor: 1
      }
    })
    .catch(e => {
      console.log(`[error] ${e.message}`)
    })

  return browser
}

module.exports = {
  launch
}
