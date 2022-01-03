const path = require('path')

/** @type {import('aegir').PartialOptions} */
const config = {
    tsRepo: true,
    docs: {
      entryPoint: "src/index.ts"
    },
    build: {
      bundlesizeMax: '231KB'
    }
}

module.exports = config
