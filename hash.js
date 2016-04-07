#!/usr/bin/env node
var argv = require('yargs')
    .usage('Usage: ./$0 -k [private key file] -s [specification file] -p [symmetric key file] -o [output encrypted spec file]')
    .example('./$0 -k private.pem -s spec.json -p AES.key -o encrypted.json')
    .help('h')
    .demand(['k','s','p','o'])
    .describe('k','Load private key')
    .describe('s','Load specification json file')
    .describe('p','Load password')
    .describe('o','Output encrypted specification file')
    .argv;

var encoding = 'base64';

//Read files
var fs = require('fs');
var key = fs.readFileSync(argv.k, 'utf8');
var spec = fs.readFileSync(argv.s, 'utf8');
var pwd = fs.readFileSync(argv.p, 'utf8');

var crypto = require('crypto'),
    algorithm = 'aes-256-ctr',
    password = pwd;

function encrypt(text){
  var cipher = crypto.createCipher(algorithm,password)
  var crypted = cipher.update(text,'utf8',encoding)
  crypted += cipher.final(encoding);
  return crypted;
}
 
function decrypt(text){
  var decipher = crypto.createDecipher(algorithm,password)
  var dec = decipher.update(text,encoding,'utf8')
  dec += decipher.final('utf8');
  return dec;
}


var NodeRSA = require('node-rsa');
var keyRSA = new NodeRSA();
keyRSA.importKey(key, 'private');
// keyRSA.importKey(publicKey, 'public');

var encrypted = encrypt(spec)
console.log('');
console.log('Generating encrypted physical hash and signature ...... ');
console.log("Encrypted hash:"+ encrypted);
console.log('');
// Sign with RSA private key
var signature = keyRSA.sign(encrypted, encoding);
console.log("signature: "+ signature);



//Write files
fs.writeFileSync(argv.o, encrypted, 'utf8');
fs.writeFileSync('signature.txt', signature, 'utf8');
