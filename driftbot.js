/**
 * Main bot runner. Add either a single site URL in a
 * puppeteer `await page.goto()` command, or a multi-page
 * flow created with Chrome dev tools recorder.
 */

const puppeteer = require('./js/puppeteer')
const handlers = require('./js/handlers')
const timeout = process.env.PAGE_TIMEOUT || 10000

;
(async () => {
  /* DO NOT EDIT - start browser session setup */
  const browser = await puppeteer.launch()
  const page = await browser.newPage()
  const client = page._client
  client.on('Network.webSocketCreated', handlers.websocket) // observe websocket connections
  page.on('response', handlers.response) // observe general connections
  page.on('console', handlers.console_) // observe console logs and warnings
  page.on('workercreated', handlers.worker) // observe webworker connection
  /* end browser session setup */

  /* start single page example */
  await page.goto("https://driftbot.io/");
  /* end single page example */

  /* start multi-page example - record with Chrome dev tools recorder */
  // await page.goto("https://www.atoms.com/");
  /* end multi-page example */

  /* DO NOT EDIT - close session and run final analysis */
  await page.waitForTimeout(timeout)
  await browser.close()
  await handlers.close()
  /* end */
})()
