"use strict";
const multiHashing = require('../build/Release/cryptonight-hashing');

const result = multiHashing.kawpow(
	Buffer.from('63543d3913fe56e6720c5e61e8d208d05582875822628f483279a3e8d9c9a8b3', 'hex'),
	Buffer.from('9b95eb33003ba288', 'hex'),
	Buffer.from('89732e5ff8711c32558a308fc4b8ee77416038a70995670e3eb84cbdead2e337', 'hex')
);

if (result !== null && result.toString('hex') === '0000000718ba5143286c46f44eee668fdf59b8eba810df21e4e2f4ec9538fc20')
	console.log('KawPow test passed');
else {
	console.log('KawPow test failed: ' + (result ? result.toString('hex') : result));
        process.exit(1);
}

