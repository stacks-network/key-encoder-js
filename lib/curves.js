
var EC = require('elliptic').ec

var alt = {
  p192: 'prime192v1',
  p224: 'secp224r1',
  p256: 'prime256v1',
  p384: 'secp384r1',
  p521: 'secp521r1'
}

var parameters = {
    secp256k1: [1, 3, 132, 0, 10],
    p192: [1, 2, 840, 10045, 3, 1, 1],
    p224: [1, 3, 132, 0, 33],
    p256: [1, 2, 840, 10045, 3, 1, 7],
    p384: [1, 3, 132, 0, 34],
    p521: [1, 3, 132, 0, 35]
}

function toCurves (parameters) {
  var curves = {}
  for (var curve in parameters) {
    curves[curve] = {
      curveParameters: parameters[curve],
      privatePEMOptions: {label: 'EC PRIVATE KEY'},
      publicPEMOptions: {label: 'PUBLIC KEY'},
      curve: new EC(curve)
    }

    if (alt[curve]) curves[alt[curve]] = curves[curve]
  }

  return curves
}

module.exports = toCurves(parameters)
