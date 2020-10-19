"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

let result = multiHashing.argon2(Buffer.from('0305a0dbd6bf05cf16e503f3a66f78007cbf34144332ecbfc22ed95c8700383b309ace1923a0964b00000008ba939a62724c0d7581fce5761e9d8a0e6a1c3f924fdd8493d1115649c05eb601', 'hex'), 2).toString('hex');
if (result == '77cf6958b3536e1f9f0d1ea165f22811ca7bc487ea9f52030b5050c17fcdd8f5')
	console.log('Argon2-Chukwa2 test passed');
else {
	console.log('Argon2-Chukwa2 test failed: ' + result);
        process.exit(1);
}