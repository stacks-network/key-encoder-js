var test = require('tape'),
    KeyEncoder = require('./index'),
    ECPrivateKeyASN = KeyEncoder.ECPrivateKeyASN,
    SubjectPublicKeyInfoASN = KeyEncoder.SubjectPublicKeyInfoASN,
    BN = require('bn.js')

var keys = [
    //secp256k1
    {
        rawPrivate: '844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5b',
        rawPublic: '04147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75',
        pemPrivate: '-----BEGIN EC PRIVATE KEY-----\n' +
        'MHQCAQEEIIRAVcyhPv14znmkw6TFq6XbDr63rp1WkGwD0zPFZo1boAcGBSuBBAAK\n' +
        'oUQDQgAEFHt56eHdMyTO6hFf9AN7bId8c3dxMUGL+ytxPv/Q9QIye5I4YVgb1VNe\n' +
        '6uAGdlJp9AT19cUiFOlyGwSqfQQKdQ==\n' +
        '-----END EC PRIVATE KEY-----',
        pemCompactPrivate: '-----BEGIN EC PRIVATE KEY-----\n' +
        'MC4CAQEEIIRAVcyhPv14znmkw6TFq6XbDr63rp1WkGwD0zPFZo1boAcGBSuBBAAK\n' +
        '-----END EC PRIVATE KEY-----',
        pemPublic: '-----BEGIN PUBLIC KEY-----\n' +
        'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEFHt56eHdMyTO6hFf9AN7bId8c3dxMUGL\n' +
        '+ytxPv/Q9QIye5I4YVgb1VNe6uAGdlJp9AT19cUiFOlyGwSqfQQKdQ==\n' +
        '-----END PUBLIC KEY-----',
        derPrivate: '30740201010420844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5ba00706052b8104000aa14403420004147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75',
        derPublic: '3056301006072a8648ce3d020106052b8104000a03420004147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75'
    },
    //secp256r1
    {
        rawPrivate: 'ff2d3419e5d1e9421ba3ad0c398369ca7c09de3ad5c163e1ce370d0df8f2f9d8',
        rawPublic: '0478b62fda69d898dfedadb897d6a8a7f0d1a9687eb8cee28b9db05a9d094ad92da36202d8499b0635b38fff3a99eaacdc7e2990807c72d8256b49f853b739872d',
        pemPrivate: '-----BEGIN EC PRIVATE KEY-----\n' +
        'MHcCAQEEIP8tNBnl0elCG6OtDDmDacp8Cd461cFj4c43DQ348vnYoAoGCCqGSM49\n' +
        'AwEHoUQDQgAEeLYv2mnYmN/trbiX1qin8NGpaH64zuKLnbBanQlK2S2jYgLYSZsG\n' +
        'NbOP/zqZ6qzcfimQgHxy2CVrSfhTtzmHLQ==\n' +
        '-----END EC PRIVATE KEY-----',
        pemPublic: '-----BEGIN PUBLIC KEY-----\n' +
        'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeLYv2mnYmN/trbiX1qin8NGpaH64\n' +
        'zuKLnbBanQlK2S2jYgLYSZsGNbOP/zqZ6qzcfimQgHxy2CVrSfhTtzmHLQ==\n' +
        '-----END PUBLIC KEY-----',
        derPrivate: '30770201010420ff2d3419e5d1e9421ba3ad0c398369ca7c09de3ad5c163e1ce370d0df8f2f9d8a00a06082a8648ce3d030107a1440342000478b62fda69d898dfedadb897d6a8a7f0d1a9687eb8cee28b9db05a9d094ad92da36202d8499b0635b38fff3a99eaacdc7e2990807c72d8256b49f853b739872d',
        derPublic: '3059301306072a8648ce3d020106082a8648ce3d0301070342000478b62fda69d898dfedadb897d6a8a7f0d1a9687eb8cee28b9db05a9d094ad92da36202d8499b0635b38fff3a99eaacdc7e2990807c72d8256b49f853b739872d'
    }
]

var curve_params = [
    [1, 3, 132, 0, 10], //secp256k1
    [1, 2, 840, 10045, 3, 1, 7], //secp256r1
]

var keyEncoder = [];
keyEncoder[0] = new KeyEncoder('secp256k1')
keyEncoder[1] = new KeyEncoder('secp256r1')

test('encodeECPrivateKeyASN', function(t) {
    t.plan(3*keys.length)

    var pemOptions =  {label: 'EC PRIVATE KEY'}

    for (let i=0; i < keys.length; i++) {
        var privateKeyObject = {
            version: new BN(1),
            privateKey: new Buffer(keys[i].rawPrivate, 'hex'),
            parameters: curve_params[i],
            publicKey: { unused: 0, data: new Buffer(keys[i].rawPublic, 'hex') }
        }

        var privateKeyPEM = ECPrivateKeyASN.encode(privateKeyObject, 'pem', pemOptions)
        t.equal(privateKeyPEM, keys[i].pemPrivate, 'encoded PEM private key should match the OpenSSL reference')

        var decodedPrivateKeyObject = ECPrivateKeyASN.decode(privateKeyPEM, 'pem', pemOptions)
        t.equal(JSON.stringify(privateKeyObject), JSON.stringify(decodedPrivateKeyObject), 'encoded-and-decoded private key object should match the original')

        var openSSLPrivateKeyObject = ECPrivateKeyASN.decode(keys[i].pemPrivate, 'pem', pemOptions)
        t.equal(JSON.stringify(privateKeyObject), JSON.stringify(openSSLPrivateKeyObject), 'private key object should match the one decoded from the OpenSSL PEM')
    }
})

test('encodeSubjectPublicKeyInfoASN', function(t) {
    t.plan(2)

    var pemOptions =  {label: 'PUBLIC KEY'}

    for (let i=0; i < keys.length; i++) {
        var publicKeyObject = {
            algorithm: {
                id: [1, 2, 840, 10045, 2, 1],
                curve: curve_params[i]
            },
            pub: {
                unused: 0,
                data: new Buffer(keys[i].rawPublic, 'hex')
            }
        }

        var publicKeyPEM = SubjectPublicKeyInfoASN.encode(publicKeyObject, 'pem', pemOptions)
        t.equal(publicKeyPEM, keys[i].pemPublic, 'encoded PEM public key should match the OpenSSL reference')
    }
})

test('encodeRawPrivateKey', function(t) {
    t.plan(4)

    for (let i=0; i < keys.length; i++) {
        var privateKeyPEM = keyEncoder[i].encodePrivate(keys[i].rawPrivate, 'raw', 'pem')
        t.equal(privateKeyPEM, keys[i].pemPrivate, 'encoded PEM private key should match the OpenSSL reference')

        var privateKeyDER = keyEncoder[i].encodePrivate(keys[i].rawPrivate, 'raw', 'der')
        console.log(privateKeyDER)
        t.equal(privateKeyDER, keys[i].derPrivate, 'encoded DER private key should match the OpenSSL reference')
    }
})

test('encodeDERPrivateKey', function(t) {
    t.plan(4)

    for (let i=0; i < keys.length; i++) {
        var rawPrivateKey = keyEncoder[i].encodePrivate(keys[i].derPrivate, 'der', 'raw')
        t.equal(rawPrivateKey, keys[i].rawPrivate, 'encoded raw private key should match the OpenSSL reference')

        var privateKeyPEM = keyEncoder[i].encodePrivate(keys[i].derPrivate, 'der', 'pem')
        t.equal(privateKeyPEM, keys[i].pemPrivate, 'encoded PEM private key should match the OpenSSL reference')
    }
})

test('encodePEMPrivateKey', function(t) {
    t.plan(4)

    for (let i=0; i < keys.length; i++) {
        var rawPrivateKey = keyEncoder[i].encodePrivate(keys[i].pemPrivate, 'pem', 'raw')
        t.equal(rawPrivateKey, keys[i].rawPrivate, 'encoded raw private key should match the OpenSSL reference')

        var privateKeyDER = keyEncoder[i].encodePrivate(keys[i].pemPrivate, 'pem', 'der')
        t.equal(privateKeyDER, keys[i].derPrivate, 'encoded DER private key should match the OpenSSL reference')
    }
})

test('encodeRawPublicKey', function(t) {
    t.plan(4)

    for (let i=0; i < keys.length; i++) {
        var publicKeyPEM = keyEncoder[i].encodePublic(keys[i].rawPublic, 'raw', 'pem')
        t.equal(publicKeyPEM, keys[i].pemPublic, 'encoded PEM public key should match the OpenSSL reference')

        var publicKeyDER = keyEncoder[i].encodePublic(keys[i].rawPublic, 'raw', 'der')
        t.equal(publicKeyDER, keys[i].derPublic, 'encoded DER public key should match the OpenSSL reference')
    }
})

test('encodeDERPublicKey', function(t) {
    t.plan(4)

    for (let i=0; i < keys.length; i++) {
        var rawPublicKey = keyEncoder[i].encodePublic(keys[i].derPublic, 'der', 'raw')
        t.equal(rawPublicKey, keys[i].rawPublic, 'encoded raw public key should match the OpenSSL reference')

        var publicKeyPEM = keyEncoder[i].encodePublic(keys[i].derPublic, 'der', 'pem')
        t.equal(publicKeyPEM, keys[i].pemPublic, 'encoded PEM public key should match the OpenSSL reference')
    }
})

test('encodePEMPublicKey', function(t) {
    t.plan(4)

    for (let i=0; i < keys.length; i++) {
        var rawPublicKey = keyEncoder[i].encodePublic(keys[i].pemPublic, 'pem', 'raw')
        t.equal(rawPublicKey, keys[i].rawPublic, 'encoded raw public key should match the OpenSSL reference')

        var publicKeyDER = keyEncoder[i].encodePublic(keys[i].pemPublic, 'pem', 'der')
        t.equal(publicKeyDER, keys[i].derPublic, 'encoded DER public key should match the OpenSSL reference')
    }
})
