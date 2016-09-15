
var EC = require('elliptic').ec
var aliases = require('./aliases')
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
  Object.keys(parameters).forEach(function (curve) {
    var cParams
    // be lazy
    Object.defineProperty(curves, curve, {
      get: function () {
        if (!cParams) {
          cParams = {
            curveParameters: parameters[curve],
            privatePEMOptions: {label: 'EC PRIVATE KEY'},
            publicPEMOptions: {label: 'PUBLIC KEY'},
            curve: new EC(curve)
          }
        }

        return cParams
      }
    })

    if (aliases[curve]) {
      Object.defineProperty(curves, aliases[curve], {
        get: function () {
          return curves[curve]
        }
      })
    }
  })

  return curves
}

module.exports = toCurves(parameters)
