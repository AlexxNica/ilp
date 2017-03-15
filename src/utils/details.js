'use strict'

const parseHeaders = require('parse-headers')
const base64url = require('./base64url')
const cryptoHelper = require('./crypto')
const Packet = require('./packet')
const DATA_DELIMITER = '\n\n'
const STATUS_LINE_REGEX = /^PSK\/1\.0$/
const KEY_HEADER_REGEX = /^hmac-sha-256 (.+)$/

function _createRequest ({
  statusLine,
  headers,
  data
}) {
  const statusLineText = statusLine ? 'PSK/1.0\n' : ''
  const headerLines = Object.keys(headers)
    .map((k) => k + ': ' + headers[k])
    .join('\n') + DATA_DELIMITER

  let rawData = data
  if (!Buffer.isBuffer(data) && typeof data === 'object') {
    rawData = Buffer.from(JSON.stringify(data), 'utf8')
  } else if (data === undefined) {
    rawData = Buffer.from([])
  }

  return Buffer.concat([
    Buffer.from(statusLineText, 'utf8'),
    Buffer.from(headerLines, 'utf8'),
    rawData
  ])
}

function createDetails ({
  unsafeHeaders,
  headers,
  secret,
  data
}) {
  if (Object.keys(unsafeHeaders)
    .map(header => header.toLowerCase())
    .indexOf('key') >= 0) {
    throw new Error('Key header may not be set manually:' +
      JSON.stringify(unsafeHeaders))
  }

  const token = cryptoHelper.getPskToken()
  const paymentKey = cryptoHelper.getPaymentKey(secret, token)

  const privateRequest = _createRequest({
    statusLine: false,
    headers,
    data
  })

  const encrypted = cryptoHelper.aesEncryptBuffer(paymentKey, privateRequest)
  const publicRequest = _createRequest({
    statusLine: true,
    headers: Object.assign({
      'Key': 'hmac-sha-256 ' + base64url(token)
    }, unsafeHeaders),

    data: encrypted
  })

  return publicRequest
}

function _parseRequest ({ request, statusLine }) {
  const dataIndex = request.indexOf(Buffer.from(DATA_DELIMITER, 'utf8'))
  if (dataIndex === -1) {
    throw new Error('invalid request: "' + request.toString('utf8') + '"')
  }

  const head = request.slice(0, dataIndex).toString('utf8')
  const data = request.slice(dataIndex + DATA_DELIMITER.length)

  const headLines = head.split('\n')
  if (statusLine) {
    // take off the first line, because it's the status line
    const statusLineText = headLines.shift()
    const match = statusLineText.match(STATUS_LINE_REGEX)
    if (!match) throw new Error('invalid status line: "' + statusLineText + '"')
  }

  const headers = parseHeaders(headLines.join('\n'))

  return {
    data,
    headers
  }
}

function parseDetails ({
  details,
  secret
}) {
  const detailsBuffer = Buffer.from(details, 'base64')
  const publicRequest = _parseRequest({
    request: detailsBuffer,
    statusLine: true
  })

  const [ , token ] = publicRequest.headers['key'].match(KEY_HEADER_REGEX) || []
  if (!token) {
    throw new Error('invalid Key header in',
      JSON.stringify(publicRequest.headers))
  }

  const paymentKey = cryptoHelper.getPaymentKey(
    secret,
    Buffer.from(token, 'base64'))

  const decrypted = cryptoHelper.aesDecryptBuffer(paymentKey, publicRequest.data)
  const privateRequest = _parseRequest({
    request: decrypted,
    statusLine: false
  })

  return {
    unsafeHeaders: publicRequest.headers,
    headers: privateRequest.headers,
    data: privateRequest.data
  }
}

function parsePacketAndDetails ({
  packet,
  secret
}) {
  const { account, amount, data } = Packet.parse(packet)
  return Object.assign(parseDetails({
    details: data,
    secret
  }), {
    account,
    amount
  })
}

module.exports = {
  _createRequest,
  _parseRequest,
  createDetails,
  parseDetails,
  parsePacketAndDetails
}
