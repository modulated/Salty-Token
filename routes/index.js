var express = require('express');
var router = express.Router();

var pg = require('pg');
var conString = process.env.dbConnection || 'postgres://localhost:5432/george';

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
		next();
	}
}, mainCtrl);

router.post('/login', function (req, res, next) {

	if (req.authorized) {
		res.locals.info = 'Already logged in!';
		next();
	}

	else if (req.body.name == '' || req.body.pass == '') {
		res.locals.info = 'Form not filled out correctly.';
		next();
	}

	else {

		var dbResult = null;

		var requestData = {
			name:req.body.name,
			pass:req.body.pass
		};

		pg.connect(conString, function(err, client, done) {
			if (err) return console.log(err);

			var query = client.query('SELECT * FROM users where name = $1',[requestData.name]);
			query.on('row', function(row) {
				dbResult = row;

			});
		});

		if (dbResult) {
			console.log(dbResult);
			requestData.hash = dbResult.hash;
			requestData.auth = bcrypt.compareSync(requestData.pass, requestData.hash);
			delete requestData.pass;
			console.log(requestData.auth);

			if (requestData.auth) {

				var jwtString = jwt.sign(requestData, jwtKey);

				res.cookie('jwt', jwtString, {maxAge: 1200000, httpOnly: true});
				res.redirect('/');
			}

			else {
				res.locals.info = 'Invalid username and password entered.';
				next();
			}
		}
		else {
			res.locals.info = 'Invalid username and password entered.';
			next();
		}
	}

}, mainCtrl);



router.post('/register', function (req, res, next) {

	if (req.authorized) {
		res.locals.info = 'Already logged in, please log out first.';
		next();
	}

	else {

		if (req.body.name == '' || req.body.pass == '') {
			res.locals.info = 'Please enter all credentials.';
			next();
		}

		else if (req.body.pass.length < 3) {
			res.locals.info = 'Password must contain at least 3 characters.';
			next();
		}

		else {
			var dbResult = null;

			var requestData = {
				name: req.body.name,
				pass: req.body.pass
			};

			requestData.hash = bcrypt.hashSync(requestData.pass, 1);
			delete requestData.pass;

			pg.connect(conString, function(err, client, done) {

				client.query('INSERT INTO users(name, hash) values($1, $2)',[requestData.name, requestData.hash]);

				//if (err) {
				//	res.locals.info = 'Username already registered.';
				//	next();
				//}

			});

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
	res.set('Location','/');
	res.render('index', { title: 'Salty Token', authorized: req.authorized, decode: JSON.stringify(req.decode, null, '\t') });
}

module.exports = router;
