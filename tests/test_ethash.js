"use strict";
const multiHashing = require('../build/Release/cryptonight-hashing');

const result = multiHashing.ethash(
	Buffer.from('f5afa3074287b2b33e975468ae613e023e478112530bc19d4187693c13943445', 'hex'),
	Buffer.from('ff4136b6b6a244ec', 'hex'),
	1257006
);

if (result !== null && result[0].toString('hex') === '0000000000095d18875acd4a2c2a5ff476c9acf283b4975d7af8d6c33d119c74')
	console.log('Ethash test result passed');
else {
	console.log('Ethash test result failed: ' + (result[0] ? result[0].toString('hex') : result[0]));
        process.exit(1);
}

if (result !== null && result[1].toString('hex') === '47da5e47804594550791c24331163c1f1fde5bc622170e83515843b2b13dbe14')
	console.log('Ethash test mix hash passed');
else {
	console.log('Ethash test mix hash failed: ' + (result[1] ? result[1].toString('hex') : result[1]));
        process.exit(1);
}


