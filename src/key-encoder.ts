import { ec as EC } from 'elliptic'
// @ts-ignore
import * as asn1 from 'asn1.js'
const BN = require('bn.js')

/**
 * Use types for the `bn.js` lib, e.g. `@types/bn.js`
 */
type BNjs = any

const ECPrivateKeyASN = asn1.define('ECPrivateKey', function () {
    // @ts-ignore
    const self = this as any
    self.seq().obj(
        self.key('version').int(),
        self.key('privateKey').octstr(),
        self.key('parameters').explicit(0).objid().optional(),
        self.key('publicKey').explicit(1).bitstr().optional()
    )
})

const SubjectPublicKeyInfoASN = asn1.define('SubjectPublicKeyInfo', function () {
    // @ts-ignore
    const self = this as any
    self.seq().obj(
        self.key('algorithm').seq().obj(
            self.key("id").objid(),
            self.key("curve").objid()
        ),
        self.key('pub').bitstr()
    )
})

interface CurveOptions {
    curveParameters: number[];
    privatePEMOptions: { label: string };
    publicPEMOptions: { label: string };
    curve: EC;
}

const curves: { [index: string]: CurveOptions } = {
    secp256k1: {
        curveParameters: [1, 3, 132, 0, 10],
        privatePEMOptions: { label: 'EC PRIVATE KEY' },
        publicPEMOptions: { label: 'PUBLIC KEY' },
        curve: new EC('secp256k1')
    }
}

interface PrivateKey {
    version: BNjs;
    privateKey: Buffer;
    parameters: number[];
    publicKey?: {
        unused: number;
        data: Buffer;
    }
}

type KeyFormat = 'raw' | 'pem' | 'der';

export default class KeyEncoder {
    static ECPrivateKeyASN = ECPrivateKeyASN
    static SubjectPublicKeyInfoASN = SubjectPublicKeyInfoASN

    algorithmID: number[]
    options: CurveOptions

    constructor(options: string | CurveOptions) {
        if (typeof options === 'string') {
            if (options !== 'secp256k1') {
                throw new Error('Unknown curve ' + options)
            }
            options = curves[options]
        }
        this.options = options
        this.algorithmID = [1, 2, 840, 10045, 2, 1]
    }

    privateKeyObject(rawPrivateKey: string, rawPublicKey: string) {
        const privateKeyObject: PrivateKey = {
            version: new BN(1),
            privateKey: Buffer.from(rawPrivateKey, 'hex'),
            parameters: this.options.curveParameters
        }

        if (rawPublicKey) {
            privateKeyObject.publicKey = {
                unused: 0,
                data: Buffer.from(rawPublicKey, 'hex')
            }
        }

        return privateKeyObject
    }

    publicKeyObject(rawPublicKey: string) {
        return {
            algorithm: {
                id: this.algorithmID,
                curve: this.options.curveParameters
            },
            pub: {
                unused: 0,
                data: Buffer.from(rawPublicKey, 'hex')
            }
        }
    }

    encodePrivate(privateKey: string | Buffer, originalFormat: KeyFormat, destinationFormat: KeyFormat): string {
        let privateKeyObject: PrivateKey

        /* Parse the incoming private key and convert it to a private key object */
        if (originalFormat === 'raw') {
            if (typeof privateKey !== 'string') {
                throw 'private key must be a string'
            }
            let keyPair = this.options.curve.keyFromPrivate(privateKey, 'hex')
            let rawPublicKey = keyPair.getPublic('hex')
            privateKeyObject = this.privateKeyObject(privateKey, rawPublicKey)
        } else if (originalFormat === 'der') {
            if (typeof privateKey !== 'string') {
                // do nothing
            } else if (typeof privateKey === 'string') {
                privateKey = Buffer.from(privateKey, 'hex')
            } else {
                throw 'private key must be a buffer or a string'
            }
            privateKeyObject = ECPrivateKeyASN.decode(privateKey, 'der')
        } else if (originalFormat === 'pem') {
            if (typeof privateKey !== 'string') {
                throw 'private key must be a string'
            }
            privateKeyObject = ECPrivateKeyASN.decode(privateKey, 'pem', this.options.privatePEMOptions)
        } else {
            throw 'invalid private key format'
        }

        /* Export the private key object to the desired format */
        if (destinationFormat === 'raw') {
            return privateKeyObject.privateKey.toString('hex')
        } else if (destinationFormat === 'der') {
            return ECPrivateKeyASN.encode(privateKeyObject, 'der').toString('hex')
        } else if (destinationFormat === 'pem') {
            return ECPrivateKeyASN.encode(privateKeyObject, 'pem', this.options.privatePEMOptions)
        } else {
            throw 'invalid destination format for private key'
        }
    }

    encodePublic(publicKey: string | Buffer, originalFormat: KeyFormat, destinationFormat: KeyFormat): string {
        let publicKeyObject

        /* Parse the incoming public key and convert it to a public key object */
        if (originalFormat === 'raw') {
            if (typeof publicKey !== 'string') {
                throw 'public key must be a string'
            }
            publicKeyObject = this.publicKeyObject(publicKey)
        } else if (originalFormat === 'der') {
            if (typeof publicKey !== 'string') {
                // do nothing
            } else if (typeof publicKey === 'string') {
                publicKey = Buffer.from(publicKey, 'hex')
            } else {
                throw 'public key must be a buffer or a string'
            }
            publicKeyObject = SubjectPublicKeyInfoASN.decode(publicKey, 'der')
        } else if (originalFormat === 'pem') {
            if (typeof publicKey !== 'string') {
                throw 'public key must be a string'
            }
            publicKeyObject = SubjectPublicKeyInfoASN.decode(publicKey, 'pem', this.options.publicPEMOptions)
        } else {
            throw 'invalid public key format'
        }

        /* Export the private key object to the desired format */
        if (destinationFormat === 'raw') {
            return publicKeyObject.pub.data.toString('hex')
        } else if (destinationFormat === 'der') {
            return SubjectPublicKeyInfoASN.encode(publicKeyObject, 'der').toString('hex')
        } else if (destinationFormat === 'pem') {
            return SubjectPublicKeyInfoASN.encode(publicKeyObject, 'pem', this.options.publicPEMOptions)
        } else {
            throw 'invalid destination format for public key'
        }
    }
}
