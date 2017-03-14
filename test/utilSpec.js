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
      assert.throws(() => Details._parseRequest(Buffer.from('garbage', 'utf8')),
        /invalid request:/)
    })

    it('should not parse a request with an invalid status line', function () {
      const request = `PSK/1.0 GARBAGE
Header: stuff

binary data goes here
      `
      assert.throws(() => Details._parseRequest(Buffer.from(request, 'utf8')),
        /invalid status line:/)
    })

    it('should not parse a request with an invalid header line', function () {
      const request = `PSK/1.0 PRIVATE
Header without a colon

binary data goes here
      `
      assert.throws(() => Details._parseRequest(Buffer.from(request, 'utf8')),
        /invalid header line:/)
    })

    it('should parse a request', function () {
      const request = `PSK/1.0 PRIVATE
Header: value

binary data goes here`

      assert.deepEqual(
        Details._parseRequest(Buffer.from(request, 'utf8')),
        { method: 'PRIVATE',
          headers: { Header: 'value' },
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

      assert.deepEqual(
        Details.parsePacketAndDetails({ packet, secret }),
        { unsafeHeaders: { unsafeHeader: 'value' },
          headers: { header: 'value' },
          data: Buffer.from('binary data', 'utf8'),
          account: 'test.alice',
          amount: '1'
        })
    })
  })
})
