"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

let result = multiHashing.cryptonight(Buffer.from('000000208c246d0b90c3b389c4086e8b672ee040d64db5b9648527133e217fbfa48da64c0f3c0a0b0e8350800568b40fbb323ac3ccdf2965de51b9aaeb939b4f11ff81c49b74a16156ff251c00000000', 'hex'), 18).toString('hex');
if (result == '84402e62b6bedafcd65f6ba13b59ff19ad7f273900c59fa49bfbb5f67e10030f')
	console.log('RandomX-Ghostrider test passed');
else {
	console.log('RandomX-Ghostrider test failed: ' + result);
        process.exit(1);
}

