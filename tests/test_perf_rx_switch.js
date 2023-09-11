"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

const ITER = 100;
const seed1  = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex');
const seed2  = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');
const seed3  = Buffer.from('0000000000000000000000000000000000000000000000000000000000000002', 'hex');

multiHashing.randomx(Buffer.from("test"), seed1, 17);
multiHashing.randomx(Buffer.from("test"), seed2, 3);
multiHashing.randomx(Buffer.from("test"), seed3, 0);

let start = Date.now();
for (let i = ITER; i; -- i) {
  multiHashing.randomx(Buffer.from("test" + i), seed1, 17);
  multiHashing.randomx(Buffer.from("test" + i), seed2, 3);
  multiHashing.randomx(Buffer.from("test" + i), seed3, 0);
}
let end = Date.now();
console.log("Perf: " + 1000 * ITER * 3 / (end - start) + " H/s");
