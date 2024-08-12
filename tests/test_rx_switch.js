"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

for (let i = 2; i; -- i) {
  { let result = multiHashing.randomx(Buffer.from('This is a test'), Buffer.from('12345678901234567890123456789012'), 22).toString('hex');
    if (result == '2d4dc87b3d1d8edf238b4adc546439388f1e9a796066f519f2c0cb2e9fe6fcd2')
    	console.log('RandomWOW test passed');
    else {
	console.log('RandomWOW test failed: ' + result);
        process.exit(1);
    }
  }

  { let result = multiHashing.randomx(Buffer.from('0c0cedabc4f8059535516f43f0f480ca4ab081ef4119fc8b1eb980e78f16cfad8fb3227f5f113e278400003e2d90c6f83a2f0f95f829455e739f8c16d5eeedad382804b2cfefea4b150e4c01', 'hex'),
    Buffer.from('1b7d5a95878b2d38be374cf3476bd07f5ea83adf2e8ca3f34aca49009af7f498', 'hex'), 3).toString('hex');
    if (result == '8ef59b356386cccba1e481c79fe1bf4423b8837d539610842a4ab576695e0800')
	console.log('RandomX-Panther test passed');
    else {
	console.log('RandomX-Panther test failed: ' + result);
        process.exit(1);
    }
  }
}

