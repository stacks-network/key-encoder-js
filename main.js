var asn1 = require('asn1.js'),
    BN = require('bn.js')

var ECPrivateKeyASN = asn1.define('ECPrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').explicit(0).objid().optional(),
    this.key('publicKey').explicit(1).bitstr().optional()
  )
})

function EllipticCurve(parameters) {
    this.parameters = parameters
    this.pemOptions = {label: 'EC PRIVATE KEY'}
}

EllipticCurve.prototype.hexToPEM = function(privateKeyHex, hexPublicKey) {
    var privateKeyObject = {
        version: new BN(1),
        privateKey: new Buffer(privateKeyHex, 'hex'),
        parameters: this.parameters
    }

    if (hexPublicKey) {
        privateKeyObject.publicKey = {
            unused: 0,
            data: new Buffer(hexPublicKey, 'hex')
        }
    }

    return ECPrivateKeyASN.encode(privateKeyObject, 'pem', this.pemOptions)
}

EllipticCurve.prototype.PEMToHex = function(privateKeyPEM) {
    var privateKeyObject = ECPrivateKeyASN.decode(privateKeyPEM, 'pem', this.pemOptions)
    return privateKeyObject.privateKey.toString('hex');
}

SECP256k1Parameters = [1, 3, 132, 0, 10]

module.exports = {
    ECPrivateKeyASN: ECPrivateKeyASN,
    EllipticCurve: EllipticCurve,
    SECP256k1Parameters: SECP256k1Parameters
}
