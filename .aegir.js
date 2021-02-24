const path = require('path')

/** @type {import('aegir').Options["build"]["config"]} */
const esbuild = {
  inject: [path.join(__dirname, 'test/fixtures/node-globals.js')]
}


/** @type {import('aegir').PartialOptions} */
const config = {
    tsRepo: true,
    docs: {
      entryPoint: "src/index.ts"
    },
    test: {
      browser :{
        config: {
          buildConfig: esbuild
        }
      }
    },
    build: {
      bundlesizeMax: '214KB',
      config: esbuild
    }
}

module.exports = config
