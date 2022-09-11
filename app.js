var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
// var session = require('express-session');
const TTLCache = require('@isaacs/ttlcache')
var passport = require('passport');
var qs = require('querystring');
var { Strategy } = require('passport-openidconnect');
const axios = require('axios');

// source and import environment variables
require('dotenv').config({ path: '.okta.env' })
const { ORG_URL, CLIENT_ID, CLIENT_SECRET } = process.env;

var indexRouter = require('./routes/index');

var app = express();

const cache = new TTLCache({ max: 1000, ttl: 5 * 60 * 1000 })
// Implement the passport-openidconnect/StateStore interface
/**
 * Store request state.
 *
 * Generates a random string and stores the value in the cache, where it will
 * be looked-up when the user is redirected back to the application.
 *
 * @param {Object} req
 * @param {Object} ctx
 * @param {Object} appState
 * @param {Function} cb
 */
cache.store = function(req, ctx, appState, meta, cb) {
  function uid(len) {
    const crypto = require('crypto');
    return crypto.randomBytes(Math.ceil(len * 3 / 4))
      .toString('base64')
      .slice(0, len);
  };
  const key = uid(24);
  const value = { ctx, appState };
  this.set(key, value);

  cb(null, key);
};

/**
 * Verify request state.
 *
 * Looks-up the state parameter in the cache where it was placed there earlier
 * by 'store'.
 *
 * @param {Object} req
 * @param {String} state
 * @param {Function} cb
 * @api protected
 */
cache.verify = function(req, state, cb) {
  const value = this.get(state);
  if (!value) {
    return cb(null, false, { message: 'Unable to verify authorization request state.' });
  }

  this.delete(state);
  return cb(null, value.ctx, value.appState);
};

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// app.use(session({
//   secret: 'CanYouLookTheOtherWay',
//   resave: false,
//   saveUninitialized: true
// }));

app.use(passport.initialize());
// app.use(passport.session());

// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
let logout_url, id_token;
let _base = ORG_URL.slice(-1) == '/' ? ORG_URL.slice(0, -1) : ORG_URL;
axios
  .get(`${_base}/.well-known/openid-configuration`)
  .then(res => {
    if (res.status == 200) {
      let { issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, end_session_endpoint } = res.data;
      logout_url = end_session_endpoint;

      // Set up passport
      passport.use('oidc', new Strategy({
        store: cache,
        issuer,
        authorizationURL: authorization_endpoint,
        tokenURL: token_endpoint,
        userInfoURL: userinfo_endpoint,
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        callbackURL: '/authorization-code/callback',
        scope: 'groups profile offline_access',
      }, (issuer, uiProfile, idProfile, context, idToken, accessToken, refreshToken, params, done) => {
        console.log(`OIDC response: ${JSON.stringify({issuer, uiProfile, idProfile, context, idToken,
          accessToken, refreshToken, params}, null, 2)}\n*****`);
        id_token = idToken;
        let profile = uiProfile._json;
        delete uiProfile._json;
        delete uiProfile._raw;
        Object.assign(profile, uiProfile);
        return done(null, profile);
      }));
    }
    else {
      console.log(`Unable to reach the well-known endpoint. Are you sure that the ORG_URL you provided (${ORG_URL}) is correct?`);
    }
  })
  .catch(error => {
    console.error(error);
  });

passport.serializeUser((user, next) => {
  next(null, user);
});

passport.deserializeUser((obj, next) => {
  next(null, obj);
});

function ensureLoggedIn(req, res, next) {
  if (req.cookies["jwt"]) {
    req.user = req.cookies["jwt"];
    return next();
  }

  res.redirect('/login')
}

app.use('/', indexRouter);

app.use('/login', (req, res, next) => {
    passport.authenticate('oidc', { session: false, callbackURL: '/authorization-code/callback' })(req, res, next);
    // console.log("*** Login response\n", res, "\n******\n");
  });

app.use('/authorization-code/callback',
  (req, res, next) => {
    if (req.query /* && req.query.code */) {// Authentication-code flow
      req.session ??= {};
      // https://github.com/jaredhanson/passport/issues/458
      passport.authenticate('oidc', { session: false, failureMessage: true, failWithError: true,
                                      callbackURL: '/authorization-code/callback' })(req, res, next);
    }
    else if (req.body && req.body.access_token) { // Implicit or Hybrid flow: re-post from implicit.html
      // ... handle access_token ...

      if (req.body.code) { // Hybrid flow: possibly retrieve refresh_token
        Object.assign(req.query, req.body); // merge req.body properties into req.query
        passport.authenticate('oidc', { session: false, failureMessage: true, failWithError: true,
                                        callbackURL: '/authorization-code/callback' })(req, res, next);
      }
    }
    else // Implicit or Hybrid flow: redirect from Authorization Server
      // POST #hash fragment as body
      res.render('implicit', { base_path: "/" });
  },
  (err, req, res, next) => {
    console.log("*** Error\n", res, "\n******\n");
    next(err);
  },
  (req, res) => {
    res.cookie('jwt', req.user);
    res.redirect('/profile');
    // console.log("*** Callback response\n", res, "\n******\n");
  }
);

app.use('/profile', ensureLoggedIn, (req, res) => {
  res.render('profile', { authenticated: !!req.user, user: req.user });
});

app.post('/logout', (req, res, next) => {
  res.clearCookie('jwt');
  // req.logout(err => {
  //   if (err) { return next(err); }
    let params = {
      id_token_hint: id_token,
      post_logout_redirect_uri: req.protocol + '://' + req.hostname + '/'
    }
    res.redirect(logout_url + '?' + qs.stringify(params));
  // });
});

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message + (err.code && ' (' + err.code + ')' || '') +
    (req.session?.messages && ": " + req.session.messages.join("\n. ") || '');
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
