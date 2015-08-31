# ECDSA Key Encoder and Decoder

#### Encoding Hex Private Keys to PEM Format

```js
var SECP256k1Parameters = require('ecdsa-key-encoder').SECP256k1Parameters,
    EllipticCurve = require('ecdsa-key-encoder').EllipticCurve

var ellipticCurve = new EllipticCurve(SECP256k1Parameters),
    privateKeyHex = '844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5b',
    publicKeyHex = '04147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75'

var privateKeyPEM = ellipticCurve.hexToPEM(privateKeyHex, publicKeyHex)
```

#### Decoding PEM Private Keys to Hex Format

```js
var decodedPrivateKeyHex = ellipticCurve.PEMToHex(privateKeyPEM)
```

