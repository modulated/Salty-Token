var express = require('express');
var router = express.Router();
var jwt = require('jsonwebtoken');
var timestamp = require('unix-timestamp');
var bcrypt = require('bcrypt');
var fs = require('fs');

var jwtKey = 'secret';
var userStore = {name:'test', hash:'$2a$04$biuo0vUYCCZU9JdiCABNO.z/QTi5buayUX2WZMAlUFvdZNjxGEroq'};



// token middleware
router.use('/', function (req, res, next) {
	if (req.cookies.jwt) {
		jwt.verify( req.cookies.jwt, jwtKey, function (err, decoded) {
			if (err) return res.send("Auth Error: " + err.message);
			req.authorized = true;
			req.decode = decoded;
			next();
		});
	}
	else {
		req.authorized = false;
		next();
	}
});


router.get('/logout', function (req, res) {
	if (req.authorized) {
		res.clearCookie('jwt');
		res.redirect('/');
	}

	else res.send("Not logged in!");
});

router.post('/login', function (req, res, next) {

	if (req.authorized) {
		res.send('Already logged in!');
	}

	else {

		var requestData = {
			name:req.body.name,
			pass:req.body.pass
		};

		requestData.auth = bcrypt.compareSync(requestData.pass, userStore[requestData.name][hash]);

		if (requestData.auth) {

			var jwtString = jwt.sign(requestData, jwtKey);

			res.cookie('jwt', jwtString, { maxAge: 1200000, httpOnly: true });
			res.redirect('/');
		}


	}

});

router.post('/register', function (req, res, next) {

	if (req.authorized) {
		res.send('Already logged in, please log out first.');
	}

	else {
		if (userStore[req.body.name]) {
			res.send('Name already registered.');
		}
		else if (req.body.name == null || req.body.pass == null) {
			res.send('Form not filled out correctly.');
		}

		else {
			var requestData = {
				name: req.body.name,
				pass: req.body.pass,
			};

			requestData.hash = bcrypt.hashSync(requestData.pass, 1);
			delete requestData.pass;

			userStore[req.body.name] = requestData;

			var jwtString = jwt.sign(requestData, jwtKey);

			res.cookie('jwt', jwtString, {maxAge: 1200000, httpOnly: true});
			res.redirect('/');
		}
	}
});


/* GET home page. */
router.get('/', function (req, res, next) {
	res.render('index', { title: 'Express', authorized: req.authorized, decode: JSON.stringify(req.decode)});
});

module.exports = router;
