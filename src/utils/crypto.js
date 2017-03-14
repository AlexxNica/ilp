'use strict'

const crypto = require('crypto')
const stringify = require('canonical-json')

const IPR_RECEIVER_ID_STRING = 'ilp_ipr_receiver_id'
const PSK_GENERATION_STRING = 'ilp_psk_generation'
const PSK_CONDITION_STRING = 'ilp_psk_condition'
const PSK_ENCRYPTION_STRING = 'ilp_key_encryption'

const RECEIVER_ID_LENGTH = 8
const SHARED_SECRET_LENGTH = 16

function getPskToken () {
  return crypto.randomBytes(16)
}

function getReceiverId (hmacKey) {
  return hmac(hmacKey, IPR_RECEIVER_ID_STRING).slice(0, RECEIVER_ID_LENGTH)
}

function getPskSharedSecret (hmacKey, token) {
  const generator = hmac(hmacKey, PSK_GENERATION_STRING)
  return hmac(generator, token).slice(0, SHARED_SECRET_LENGTH)
}

function hmac (key, message) {
  const h = crypto.createHmac('sha256', key)
  h.update(message, 'utf8')
  return h.digest()
}

function hmacJsonForPskCondition (obj, sharedSecret) {
  const pskConditionKey = hmac(sharedSecret, PSK_CONDITION_STRING)
  const jsonString = stringify(obj)
  const hmacDigest = hmac(pskConditionKey, jsonString)
  return hmacDigest
}

// turn buffer into encrypted buffer
function aesEncryptBuffer (buffer, sharedSecret) {
  const pskEncryptionKey = hmac(sharedSecret, PSK_ENCRYPTION_STRING)
  const cipher = crypto.createCipher('aes-256-ctr', pskEncryptionKey)

  return Buffer.concat([
    cipher.update(buffer),
    cipher.final()
  ])
}

// turn buffer into decrypted buffer
function aesDecryptBuffer (encrypted, sharedSecret) {
  const pskEncryptionKey = hmac(sharedSecret, PSK_ENCRYPTION_STRING)
  const decipher = crypto.createDecipher('aes-256-ctr', pskEncryptionKey)

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ])
}

module.exports = {
  hmacJsonForPskCondition,
  aesEncryptBuffer,
  aesDecryptBuffer,
  getPskToken,
  getReceiverId,
  getPskSharedSecret
}
