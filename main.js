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

function SECP256k1PrivateKey() {
}

SECP256k1PrivateKey.ec = new EC('secp256k1')
SECP256k1PrivateKey.parameters = [1, 3, 132, 0, 10]
SECP256k1PrivateKey.pemOptions = {label: 'EC PRIVATE KEY'}

SECP256k1PrivateKey.hexToPEM = function(privateKeyHex, hexPublicKey) {
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

    return ECPrivateKey.encode(privateKeyObject, 'pem', this.pemOptions)
}

SECP256k1PrivateKey.PEMToHex = function(privateKeyPEM) {
    var privateKeyObject = ECPrivateKey.decode(privateKeyPEM, 'pem', this.pemOptions)
    return privateKeyObject.privateKey.toString('hex');
}

module.exports = {
    ECPrivateKey: ECPrivateKey,
    SECP256k1PrivateKey: SECP256k1PrivateKey
}
