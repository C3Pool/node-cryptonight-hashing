"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

const ITER = 200;
let input = Buffer.from('000000208c246d0b90c3b389c4086e8b672ee040d64db5b9648527133e217fbfa48da64c0f3c0a0b0e8350800568b40fbb323ac3ccdf2965de51b9aaeb939b4f11ff81c49b74a16156ff251c00000000', 'hex');

let start = Date.now();
for (let i = ITER; i; -- i) {
  multiHashing.cryptonight(input, 18);
}
let end = Date.now();
console.log("Perf: " + 1000 * ITER / (end - start) + " H/s");
