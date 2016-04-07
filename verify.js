#!/usr/bin/env node
var argv = require('yargs')
.usage('Usage: ./$0 -k [public key file] -f [encrypted file] -p [symmetric key file] -s [signature]')
.example('./$0 -k public.pem -f encrypted.json -p AES.key -s signature.txt')
.help('h')
.demand(['k','f','p','s'])
.describe('k','Load public key file')
.describe('f','Load encrypted specification file')
.describe('p','Load password file')
.describe('s','Load signature file')
.argv;

var encoding = 'base64';

var inquirer = require("inquirer");
var _ = require('lodash');

//Read files
var fs = require('fs');
var key = fs.readFileSync(argv.k, 'utf8');
var file = fs.readFileSync(argv.f, 'utf8');
var pwd = fs.readFileSync(argv.p, 'utf8');
var signature = fs.readFileSync(argv.s, 'utf8');

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
keyRSA.importKey(key, 'public');

console.log('');
console.log('Verifying specification authentication ......');
console.log('');
//Verify part
var verify = keyRSA.verify(file, signature, 'utf8', encoding);

if(verify)
	console.log('Verified specification.');
else
	console.log('Fake specification.');
console.log('');

var plaintext = decrypt(file);
var jsonContent = JSON.parse(plaintext);

console.log('Retrieving quality standards for Product ID ' +  jsonContent.productID + ' ......');
console.log('');
console.log("Constraint:");
for(var key in jsonContent.constraints){
	console.log(key+ ": "+ jsonContent.constraints[key]);
}
console.log("");

var questions = [];
for(var key in jsonContent.constraints){
	var q = {
			type: "input",
			name: key,
			message: "Input "+ key+ " measure:"
	};
	questions.push(q);

}


function parseConstraint(answers){
	console.log('');
	//check for constraints
	var flag = true;
	for(var qc in answers){
		var measure = answers[qc];
		var constraint = jsonContent.constraints[qc];
		var range = constraint.replace(/[a-zA-Z]+/g,'');
		if(range.includes("-")){
			var r = range.split("-");
			if(measure<r[0] || measure> r[1]){
				console.log(qc+ " out of specification!");
				flag = false;
			}
		}
		else if(range.includes("<")){
			var r = range.split("<");
			if(measure>= r[1]){
				console.log(qc+ " out of specification!");
				flag = false;
			}
		}
		else if(range.includes(">")){
			var r = range.split(">");
			if(measure<= r[1]){
				console.log(qc+ " out of specification!");
				flag = false;
			}
		}
	}
	if(flag){
		console.log("Pass Quality Control Standards.")
	}
	console.log('');
       
}


inquirer.prompt( questions, function(answers){
	parseConstraint(answers);
});

