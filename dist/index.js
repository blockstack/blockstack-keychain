
'use strict'

if (process.env.NODE_ENV === 'production') {
  module.exports = require('./keychain.cjs.production.min.js')
} else {
  module.exports = require('./keychain.cjs.development.js')
}
