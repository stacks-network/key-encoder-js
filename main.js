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

/******
 * Hand-crafted Private Key
 ******/

var publicKeyHex = '04147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75',
    privateKeyHex = '844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5b',
    options =  {label: 'EC PRIVATE KEY'}
var publicKeyBitstr = { data: new Buffer(publicKeyHex, 'hex'), unused: 0 }
var encodedPrivateKey = ECPrivateKey.encode({
    version: new BN(1),
    privateKey: new Buffer(privateKeyHex, 'hex'),
    parameters: '1.3.132.0.10'.split('.'),
    publicKey: publicKeyBitstr
}, 'pem', options)
var decodedPrivateKey = ECPrivateKey.decode(encodedPrivateKey, 'pem', options)

/******
 * OpenSSL Private Key
 ******/

var openSSLEncodedPrivateKey = '-----BEGIN EC PRIVATE KEY-----\n' +
'MHQCAQEEIIRAVcyhPv14znmkw6TFq6XbDr63rp1WkGwD0zPFZo1boAcGBSuBBAAK\n' +
'oUQDQgAEFHt56eHdMyTO6hFf9AN7bId8c3dxMUGL+ytxPv/Q9QIye5I4YVgb1VNe\n' +
'6uAGdlJp9AT19cUiFOlyGwSqfQQKdQ==\n' +
'-----END EC PRIVATE KEY-----'
var openSSLDecodedPrivateKey = ECPrivateKey.decode(openSSLEncodedPrivateKey, 'pem', options)
var openSSLReencodedPrivateKey = ECPrivateKey.encode(openSSLDecodedPrivateKey, 'pem', options)
var openSSLDecodedPrivateKeyHex = openSSLDecodedPrivateKey.privateKey.toString('hex')
var openSSLDecodedPublicKeyHex = openSSLDecodedPrivateKey.publicKey.data.toString('hex')

/******
 * Printing
 ******/

console.log('\n\n**************\nHand-crafted Private Key\n**************')
console.log('\nEncoded private key:')
console.log(encodedPrivateKey)
console.log('\nDecoded private key:')
console.log(decodedPrivateKey)

console.log('\n\n**************\nOpenSSL Private Key\n**************')
console.log('\nOriginal encoded private key:')
console.log(openSSLEncodedPrivateKey)
console.log('\nDecoded private key:')
console.log(openSSLDecodedPrivateKey)
console.log('\nDecoded private Key (Hex):')
console.log(openSSLDecodedPrivateKeyHex)
console.log('\nDecoded public key (Hex):')
console.log(openSSLDecodedPublicKeyHex)
console.log('\nRe-encoded private key:')
console.log(openSSLReencodedPrivateKey)
