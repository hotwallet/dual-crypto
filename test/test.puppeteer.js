const puppeteer = require('puppeteer')
const http = require('http')
const express = require('express')

const PORT = process.env.PORT || 8081
const URL = `http://localhost:${PORT}/test/index.html`

const app = express()
const server = http.createServer(app).listen(PORT)
app.use(express.static(`${__dirname}/../`))
console.log(URL)

const runTests = async () => {
  const browser = await puppeteer.launch({
    args: ['--no-sandbox']
  })
  const page = await browser.newPage()
  page.emulate({
    viewport: { width: 500, height: 500 },
    userAgent: ''
  })
  page.on('console', msg => {
    const message = msg.text()
    console.log(message)
    if (message === 'decryptedMessage: Satoshi Nakamoto') {
      browser.close()
      process.exit(0)
    }
  })
  await page.goto(URL)
}

runTests()

