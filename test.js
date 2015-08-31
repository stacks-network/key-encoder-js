var test = require('tape'),
    main = require('./main'),
    ECPrivateKeyASN = main.ECPrivateKeyASN,
    SubjectPublicKeyInfoASN = main.SubjectPublicKeyInfoASN,
    KeyEncoder = main.KeyEncoder,
    SECP256k1Parameters = main.SECP256k1Parameters,
    BN = require('bn.js')

var privateKeyHex = '844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5b',
    publicKeyHex = '04147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75',
    openSSLPrivateKeyPEM = '-----BEGIN EC PRIVATE KEY-----\n' +
    'MHQCAQEEIIRAVcyhPv14znmkw6TFq6XbDr63rp1WkGwD0zPFZo1boAcGBSuBBAAK\n' +
    'oUQDQgAEFHt56eHdMyTO6hFf9AN7bId8c3dxMUGL+ytxPv/Q9QIye5I4YVgb1VNe\n' +
    '6uAGdlJp9AT19cUiFOlyGwSqfQQKdQ==\n' +
    '-----END EC PRIVATE KEY-----',
    openSSLPrivateKeyPEMCompact = '-----BEGIN EC PRIVATE KEY-----\n' +
    'MC4CAQEEIIRAVcyhPv14znmkw6TFq6XbDr63rp1WkGwD0zPFZo1boAcGBSuBBAAK\n' +
    '-----END EC PRIVATE KEY-----',
    openSSLPublicKeyPEM = '-----BEGIN PUBLIC KEY-----\n' +
    'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEFHt56eHdMyTO6hFf9AN7bId8c3dxMUGL\n' +
    '+ytxPv/Q9QIye5I4YVgb1VNe6uAGdlJp9AT19cUiFOlyGwSqfQQKdQ==\n' +
    '-----END PUBLIC KEY-----'

test('testECPrivateKey', function(t) {
    t.plan(3)

    var secp256k1Parameters = [ 1, 3, 132, 0, 10 ],
        pemOptions =  {label: 'EC PRIVATE KEY'}

    var privateKeyObject = {
        version: new BN(1),
        privateKey: new Buffer(privateKeyHex, 'hex'),
        parameters: secp256k1Parameters,
        publicKey: { unused: 0, data: new Buffer(publicKeyHex, 'hex') }
    }

    var privateKeyPEM = ECPrivateKeyASN.encode(privateKeyObject, 'pem', pemOptions)
    t.equal(privateKeyPEM, openSSLPrivateKeyPEM)

    var decodedPrivateKeyObject = ECPrivateKeyASN.decode(privateKeyPEM, 'pem', pemOptions)
    t.equal(JSON.stringify(privateKeyObject), JSON.stringify(decodedPrivateKeyObject))

    var openSSLPrivateKeyObject = ECPrivateKeyASN.decode(openSSLPrivateKeyPEM, 'pem', pemOptions)
    t.equal(JSON.stringify(privateKeyObject), JSON.stringify(openSSLPrivateKeyObject))
})

test('testECPublicKey', function(t) {
    t.plan(1)

    var secp256k1Parameters = [ 1, 3, 132, 0, 10 ],
        pemOptions =  {label: 'PUBLIC KEY'}

    var publicKeyObject = {
        algorithm: {
            id: [1, 2, 840, 10045, 2, 1],
            curve: secp256k1Parameters
        },
        pub: {
            unused: 0,
            data: new Buffer(publicKeyHex, 'hex')
        }
    }

    var publicKeyPEM = SubjectPublicKeyInfoASN.encode(publicKeyObject, 'pem', pemOptions)
    t.equal(publicKeyPEM, openSSLPublicKeyPEM)
})

test('testSECP256k1PrivateKey', function(t) {
    t.plan(3)

    var keyEncoder = new KeyEncoder(SECP256k1Parameters)

    var privateKeyPEM = keyEncoder.hexToPrivatePEM(privateKeyHex, publicKeyHex)
    t.equal(privateKeyPEM, openSSLPrivateKeyPEM)

    var privateKeyPEMCompact = keyEncoder.hexToPrivatePEM(privateKeyHex)
    t.equal(privateKeyPEMCompact, openSSLPrivateKeyPEMCompact)

    var decodedPrivateKeyHex = keyEncoder.privatePEMToHex(privateKeyPEM)
    t.equal(decodedPrivateKeyHex, privateKeyHex)
})

test('testSECP256k1PublicKey', function(t) {
    t.plan(2)

    var keyEncoder = new KeyEncoder(SECP256k1Parameters)

    var publicKeyPEM = keyEncoder.hexToPublicPEM(publicKeyHex)
    t.equal(publicKeyPEM, openSSLPublicKeyPEM)

    var decodedPublicKeyHex = keyEncoder.publicPEMToHex(publicKeyPEM)
    t.equal(decodedPublicKeyHex, publicKeyHex)
})
