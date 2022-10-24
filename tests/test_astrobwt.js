"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

let result = multiHashing.astrobwt(Buffer.from('0305a0dbd6bf05cf16e503f3a66f78007cbf34144332ecbfc22ed95c8700383b309ace1923a0964b00000008ba939a62724c0d7581fce5761e9d8a0e6a1c3f924fdd8493d1115649c05eb601', 'hex'), 0).toString('hex');
if (result == '7e8844f2d6b7a43498fe6d226527689023da8a52f9fc4ec69e5aaaa63edce1c1')
	console.log('AstroBWT (DERO) test passed');
else {
	console.log('AstroBWT (DERO) test failed: ' + result);
                process.exit(1);
}



