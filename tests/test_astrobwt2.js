"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

let result = multiHashing.astrobwt(Buffer.from('0305a0dbd6bf05cf16e503f3a66f78007cbf34144332ecbfc22ed95c8700383b309ace1923a0964b00000008ba939a62724c0d7581fce5761e9d8a0e6a1c3f924fdd8493d1115649c05eb601', 'hex'), 1).toString('hex');
if (result == '489ed2661427986503fb8725e1d398da27ee253db4378798bf5a5c94ee0ce22a')
	console.log('AstroBWT (DERO-HE) test passed');
else {
	console.log('AstroBWT (DERO-HE) test failed: ' + result);
                process.exit(1);
}

