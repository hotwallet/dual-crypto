const http = require('http')
const express = require('express')

const port = process.env.PORT || 8081

const app = express()

const server = http.createServer(app).listen(port)

app.use(express.static(`${__dirname}/../`))

console.log(`http://localhost:${port}/test/index.html`)