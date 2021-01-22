"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

const ITER = 200;
let input1 = Buffer.from('f5afa3074287b2b33e975468ae613e023e478112530bc19d4187693c13943445', 'hex');
let input2 = Buffer.from('ff4136b6b6a244ec', 'hex');

let start = Date.now();
for (let i = ITER; i; -- i) {
  multiHashing.ethash(input1, input2, 1257006+i);
}
let end = Date.now();
console.log("Perf: " + 1000 * ITER / (end - start) + " H/s");