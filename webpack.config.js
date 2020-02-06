module.exports = {
  entry: "./src/index.ts",
  mode: "production",
  output: {
    filename: "dist/bundle.js"
  },
  node: {
    fs: "empty"
  },
  resolve: {
    extensions: [".ts", ".js"],
  },
  module: {
    rules: [
      {test: /\.ts$/, use: {loader: "ts-loader", options: {transpileOnly: true}}}
    ],
  },

};
