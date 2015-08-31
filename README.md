# ECDSA Key Encoder and Decoder

#### Installation

```
$ npm install ecdsa-key-encoder
```

#### Getting Started

First, import the necessary modules and classes:

```js
var EllipticCurve = require('ecdsa-key-encoder').EllipticCurve,
    SECP256k1Parameters = require('ecdsa-key-encoder').SECP256k1Parameters
```

Next, define the curve and hex keys to be used:

```js
var ellipticCurve = new EllipticCurve(SECP256k1Parameters),
    privateKeyHex = '844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5b',
    publicKeyHex = '04147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75'
```

*Note that the parameters for SECP256k1 (`[1, 3, 132, 0, 10]`) are already provided but you can pass your own in for any curve you'd like.*

#### Encoding PEM Private Keys

```js
ellipticCurve.hexToPEM(privateKeyHex, publicKeyHex)
```

*Note that including the public key hex is recommended but optional. Excluding it will result in a more compact PEM:*

```js
ellipticCurve.hexToPEM(privateKeyHex)
```

#### Decoding PEM Private Keys

```js
ellipticCurve.PEMToHex(privateKeyPEM)
```
