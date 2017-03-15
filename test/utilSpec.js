'use strict'

const chai = require('chai')
const assert = chai.assert
const base64url = require('../src/utils/base64url')
const Packet = require('../src/utils/packet')
const Details = require('../src/utils/details')
const Utils = require('../src/utils')

describe('Utils', function () {
  describe('details', function ()  {
    it('should not parse an invalid request', function () {
      assert.throws(() => Details._parseRequest({
        request: Buffer.from('garbage', 'utf8'),
        statusLine: true 
      }),
        /invalid request:/)
    })

    it('should not parse a request with an invalid status line', function () {
      const request = `PSK/1.0 GARBAGE
Header: stuff

binary data goes here
      `
      assert.throws(() => Details._parseRequest({
        request: Buffer.from(request, 'utf8'),
        statusLine: true
      }),
        /invalid status line:/)
    })

    it('should parse a request', function () {
      const request = `PSK/1.0
Header: value

binary data goes here`

      assert.deepEqual(
        Details._parseRequest({
          request: Buffer.from(request, 'utf8'),
          statusLine: true
        }),
        { headers: { header: 'value' },
          data: Buffer.from('binary data goes here', 'utf8')
        })
    })

    it('should parse an ILP packet with PSK details inside', function () {
      const secret = Buffer.from('secret', 'utf8')
      const packet = Packet.serialize({
        account: 'test.alice',
        amount: '1',
        data: base64url(Details.createDetails({
          headers: { header: 'value' },
          unsafeHeaders: { unsafeHeader: 'value' },
          data: Buffer.from('binary data', 'utf8'),
          secret
        }))
      })

      const parsed = Details.parsePacketAndDetails({ packet, secret })
      assert.deepEqual(
        parsed,
        { unsafeHeaders: {
            // the key field isn't deterministic
            key: parsed.unsafeHeaders.key,
            unsafeheader: 'value'
          },
          headers: { header: 'value' },
          data: Buffer.from('binary data', 'utf8'),
          account: 'test.alice',
          amount: '1'
        })
    })
  })
})
