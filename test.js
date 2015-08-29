var test = require('tape'),
    ECPrivateKey = require('./main').ECPrivateKey,
    BN = require('bn.js')

test('encodeAndDecodeSECP256k1PEM', function(t) {
    t.plan(3)

    var privateKeyHex = '844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5b',
        publicKeyHex = '04147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75',
        secp256k1Parameters = [ 1, 3, 132, 0, 10 ],
        pemOptions =  {label: 'EC PRIVATE KEY'},
        openSSLPrivateKeyPEM = '-----BEGIN EC PRIVATE KEY-----\n' +
        'MHQCAQEEIIRAVcyhPv14znmkw6TFq6XbDr63rp1WkGwD0zPFZo1boAcGBSuBBAAK\n' +
        'oUQDQgAEFHt56eHdMyTO6hFf9AN7bId8c3dxMUGL+ytxPv/Q9QIye5I4YVgb1VNe\n' +
        '6uAGdlJp9AT19cUiFOlyGwSqfQQKdQ==\n' +
        '-----END EC PRIVATE KEY-----'

    var privateKeyObject = {
        version: new BN(1),
        privateKey: new Buffer(privateKeyHex, 'hex'),
        parameters: secp256k1Parameters,
        publicKey: { unused: 0, data: new Buffer(publicKeyHex, 'hex') }
    }

    var privateKeyPEM = ECPrivateKey.encode(privateKeyObject, 'pem', pemOptions)
    t.equal(privateKeyPEM, openSSLPrivateKeyPEM)

    var decodedPrivateKeyObject = ECPrivateKey.decode(privateKeyPEM, 'pem', pemOptions)
    t.equal(JSON.stringify(privateKeyObject), JSON.stringify(decodedPrivateKeyObject))

    var openSSLPrivateKeyObject = ECPrivateKey.decode(openSSLPrivateKeyPEM, 'pem', pemOptions)
    t.equal(JSON.stringify(privateKeyObject), JSON.stringify(openSSLPrivateKeyObject))
})
