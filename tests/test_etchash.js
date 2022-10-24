"use strict";
const multiHashing = require('../build/Release/cryptonight-hashing');

const result = multiHashing.etchash(
        Buffer.from('053690289a0a9dac132c268d6ffe64ad8e025b74eefa61b51934c57d2a49d9e4', 'hex'),
        Buffer.from('fe09000002a784b0', 'hex'),
        15658542
);

if (result !== null && result[0].toString('hex') === '0000000d4899e38dbd9ac5bdc3726e34669986f53af0c60f50c5aa54e7fa4ed0')
        console.log('Etchash test result passed');
else {
        console.log('Etchash test result failed: ' + (result[0] ? result[0].toString('hex') : result[0]));
        process.exit(1);
}

if (result !== null && result[1].toString('hex') === '9b4f5f7321d7b132ea2cc8d4eef5f61d906658cbf7bc49edd77c9a192c290697')
        console.log('Etchash test mix hash passed');
else {
        console.log('Etchash test mix hash failed: ' + (result[1] ? result[1].toString('hex') : result[1]));
        process.exit(1);
}