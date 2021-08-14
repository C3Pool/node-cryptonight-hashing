"use strict";
const multiHashing = require('cryptonight-hashing');

const extraNonce1 = Buffer.from("9618", 'hex');
const extraNonce2 = Buffer.from("33e73592d373", 'hex');
const nonce = "961833e73592d373";
const height = 535357;
const msg = Buffer.from("9dbb7796a8c29559d5906331975dae9e16f8513ee4864692dcee05fd12c09e6d", 'hex');

function serializeCoinbase(msg, extraNonce1, extraNonce2){
  return Buffer.concat([
    msg,
    extraNonce1,
    extraNonce2
  ]);
};

const result = multiHashing.autolykos2_hashes(serializeCoinbase(msg, extraNonce1, extraNonce2), height);

if (result !== null && result[0].toString('hex') === '10cf53f111fa6236ab59d87a70888fca6bd4d8a9dec816df013b94b91f8e09d8')
	console.log('autolykos2 test passed');
else {
	console.log('autolykos2 test failed: ' + (result ? result[0].toString('hex') : result[0]));
        process.exit(1);
}

