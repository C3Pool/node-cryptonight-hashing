"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

const ITER = 10000000;
let input1 = Buffer.from('63543d3913fe56e6720c5e61e8d208d05582875822628f483279a3e8d9c9a8b3', 'hex');
let input2 = Buffer.from('9b95eb33003ba288', 'hex');
let input3 = Buffer.from('89732e5ff8711c32558a308fc4b8ee77416038a70995670e3eb84cbdead2e337', 'hex');

let start = Date.now();
for (let i = ITER; i; -- i) {
  multiHashing.kawpow(input1, input2, input3);
}
let end = Date.now();
console.log("Perf: " + 1000 * ITER / (end - start) + " H/s");