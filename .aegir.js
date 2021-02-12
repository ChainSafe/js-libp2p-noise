const path = require('path')
const esbuild = {
  inject: [path.join(__dirname, 'test/fixtures/node-globals.js')]
}
module.exports = {
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
      bundlesizeMax: '228KB',
      config: esbuild
    }
}
