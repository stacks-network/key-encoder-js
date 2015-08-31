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

var SubjectPublicKeyInfoASN = asn1.define('SubjectPublicKeyInfo', function() {
    this.seq().obj(
        this.key('algorithm').seq().obj(
            this.key("id").objid(),
            this.key("curve").objid()
        ),
        this.key('pub').bitstr()
    )
})

function KeyEncoder(curveParameters) {
    this.parameters = curveParameters
    this.privatePEMOptions = {label: 'EC PRIVATE KEY'}
    this.publicPEMOptions = {label: 'PUBLIC KEY'}
    this.algorithmID = [1, 2, 840, 10045, 2, 1]
}

KeyEncoder.prototype.hexToPrivatePEM = function(privateKeyHex, hexPublicKey) {
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

    return ECPrivateKeyASN.encode(privateKeyObject, 'pem', this.privatePEMOptions)
}

KeyEncoder.prototype.privatePEMToHex = function(privateKeyPEM) {
    var privateKeyObject = ECPrivateKeyASN.decode(privateKeyPEM, 'pem', this.privatePEMOptions)
    return privateKeyObject.privateKey.toString('hex');
}

KeyEncoder.prototype.hexToPublicPEM = function(publicKeyHex) {
    var publicKeyObject = {
        algorithm: {
            id: this.algorithmID,
            curve: this.parameters
        },
        pub: {
            unused: 0,
            data: new Buffer(publicKeyHex, 'hex')
        }
    }

    return SubjectPublicKeyInfoASN.encode(publicKeyObject, 'pem', this.publicPEMOptions)
}

KeyEncoder.prototype.publicPEMToHex = function(publicKeyPEM) {
    var publicKeyObject = SubjectPublicKeyInfoASN.decode(publicKeyPEM, 'pem', this.publicPEMOptions)
    return publicKeyObject.pub.data.toString('hex')
}

SECP256k1Parameters = [1, 3, 132, 0, 10]

module.exports = {
    ECPrivateKeyASN: ECPrivateKeyASN,
    SubjectPublicKeyInfoASN: SubjectPublicKeyInfoASN,
    KeyEncoder: KeyEncoder,
    SECP256k1Parameters: SECP256k1Parameters
}
