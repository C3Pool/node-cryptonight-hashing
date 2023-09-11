"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

let result = multiHashing.randomx(Buffer.from('This is a test'), Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex'), 17).toString('hex');
if (result == '7f7d2ec8dd966f1bacdb19f450255a46eef353d917758f775559df6f6431ce33')
	console.log('RandomWOW test passed');
else {
	console.log('RandomWOW test failed: ' + result);
        process.exit(1);
}

