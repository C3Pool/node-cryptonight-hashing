"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

let result = multiHashing.cryptonight(Buffer.from('0100000000000000000000000000000000000000000000000000000000000000000000001ccca66a44f8bd5545c3164a3a76da50395328c9075633775bc4c8798fd6772b700d215cf0ff0f1e00000000', 'hex'), 19).toString('hex');
if (result == '2e4f857aa81008c4d1fe9acd7489e84d3bc55b7054e6c02b2c0e1b76cca0da7b')
	console.log('RandomX-Flex test passed');
else {
	console.log('RandomX-Flex test failed: ' + result);
        process.exit(1);
}

