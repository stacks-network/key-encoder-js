/******
 * Private Key PEM Encoding and Decoding
 ******/

var asn1 = require('asn1.js'),
    BN = require('bn.js'),
    EC = require('elliptic').ec

var ECPrivateKey = asn1.define('ECPrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').explicit(0).objid().optional(),
    this.key('publicKey').explicit(1).bitstr().optional()
  )
})

module.exports = {
    ECPrivateKey: ECPrivateKey
}
