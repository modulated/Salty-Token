var express = require('express');
var router = express.Router();
var jwt = require('jsonwebtoken');
var bcrypt = require('bcrypt');

var jwtKey = 'secret';
userStore = {};


// token middleware
router.use('/', function (req, res, next) {
	if (req.cookies.jwt) {
		jwt.verify( req.cookies.jwt, jwtKey, function (err, decoded) {
			if (err) {
				res.locals.info = ('Auth Error: ' + err.message + '.');
				next();
			}
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

// routes

router.get('/logout', function (req, res, next) {
	if (req.authorized) {
		res.clearCookie('jwt');
		res.redirect('/');
	}

	else {
		res.locals.info = "Not logged in!";
		res.writeHead(302, {Location:'/'});
		next();
	}
}, mainCtrl);

router.post('/login', function (req, res, next) {

	if (req.authorized) {
		res.locals.info = 'Already logged in!';
		res.writeHead(302, {Location:'/'});
		next();
	}

	else if (req.body.name == '' || req.body.pass == '') {
		res.locals.info = 'Form not filled out correctly.';
		res.writeHead(302, {Location:'/'});
		next();
	}

	else {

		var requestData = {
			name:req.body.name,
			pass:req.body.pass
		};

		if (userStore[requestData.name]) {

			requestData.hash = userStore[requestData.name]['hash'];
			requestData.auth = bcrypt.compareSync(requestData.pass, requestData.hash);
			delete requestData.pass;

			if (requestData.auth) {

				var jwtString = jwt.sign(requestData, jwtKey);

				res.cookie('jwt', jwtString, {maxAge: 1200000, httpOnly: true});
				res.redirect('/');
			}

			else {
				res.locals.info = 'Invalid username and password entered.';
				res.writeHead(302, {Location:'/'});
				next();
			}
		}
		else {
			res.locals.info = 'Invalid username and password entered.';
			res.writeHead(302, {Location:'/'});
			next();
		}
	}

}, mainCtrl);



router.post('/register', function (req, res, next) {

	if (req.authorized) {
		res.locals.info = 'Already logged in, please log out first.';
		res.writeHead(302, {Location:'/'});
		next();
	}

	else {

		if (req.body.name == '' || req.body.pass == '') {
			res.locals.info = 'Please enter all credentials.';
			res.writeHead(302, {Location:'/'});
			next();
		}

		else if (userStore[req.body.name]) {
			res.locals.info = 'Username already registered.';
			res.writeHead(302, {Location:'/'});
			next();
		}

		else if (req.body.pass.length < 3) {
			res.locals.info = 'Password must contain at least 3 characters.';
			res.writeHead(302, {Location:'/'});
			next();
		}

		else {
			var requestData = {
				name: req.body.name,
				pass: req.body.pass
			};

			requestData.hash = bcrypt.hashSync(requestData.pass, 1);
			delete requestData.pass;

			userStore[req.body.name] = requestData;

			var jwtString = jwt.sign(requestData, jwtKey);

			res.cookie('jwt', jwtString, {maxAge: 1200000, httpOnly: true});
			res.redirect('/');
		}
	}
}, mainCtrl);


/* GET home page. */
router.get('/', mainCtrl);

// Render home page with context.
function mainCtrl (req,res) {
	res.render('index', { title: 'Express', authorized: req.authorized, decode: JSON.stringify(req.decode, null, '\t') });
}

module.exports = router;
