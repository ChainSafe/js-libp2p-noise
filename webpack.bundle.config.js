
const BundleAnalyzerPlugin = require('webpack-bundle-analyzer').BundleAnalyzerPlugin;

module.exports = {
  entry: "./src/index.ts",
  mode: "production",
  output: {
    filename: "../bundle/bundle.js"
  },
  node: {
    fs: "empty"
  },
  resolve: {
    extensions: [".ts", ".js"],
  },
  module: {
    rules: [
      {test: /\.ts$/, exclude: [/node_modules/], use: {loader: "babel-loader", options: require("./babel.web.config")}}
    ],
  },
  plugins: [
    new BundleAnalyzerPlugin()
  ]
};
