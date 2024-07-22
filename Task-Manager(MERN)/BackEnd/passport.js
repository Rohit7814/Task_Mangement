const passport = require("passport");
require("dotenv").config();
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const LocalStrategy = require("passport-local").Strategy;
const authModel = require("./Models/Model");
const bcrypt = require("bcrypt");

const googleCredentials = {
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:8080/google/callback",
};

const fbCredentials = {
  clientID: process.env.FACEBOOK_CLIENT_ID,
  clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
  callbackURL: "http://localhost:8080/facebook/callback",
  profileFields: ["id", "email", "displayName", "picture.type(large)"],
};

const callback = async (accessToken, refreshToken, profile, cb) => {
  try {
    const newUser = {
      userName: profile.displayName,
      email: profile.emails[0].value,
      googleId: profile.id,
      picUrl: profile.photos[0].value,
    };

    let user = await authModel.findOne({ googleId: profile.id });
    if (!user) {
      user = await authModel.create(newUser);
    }

    cb(null, user);
  } catch (err) {
    cb(err);
  }
};

const callback2 = async (accessToken, refreshToken, profile, cb) => {
  try {
    const newUser = {
      userName: profile.displayName,
      fbId: profile.id,
      email: profile.emails[0].value,
      picUrl: profile.photos[0].value,
    };

    let user = await authModel.findOne({ fbId: profile.id });
    if (!user) {
      user = await authModel.create(newUser);
    }

    cb(null, user);
  } catch (err) {
    cb(err);
  }
};

const LocalStrategycallback = (email, password, done) => {
  authModel.findOne({ email: email })
    .then((user) => {
      if (!user) {
        return done(null, false, { message: "User not found" });
      }
      bcrypt.compare(password, user.password)
        .then((isValid) => {
          if (isValid) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Incorrect password" });
          }
        })
        .catch((err) => {
          return done(err);
        });
    })
    .catch((err) => {
      return done(err);
    });
};
//console.log(googleCredentials);
passport.use(new GoogleStrategy(googleCredentials, callback));
passport.use(new FacebookStrategy(fbCredentials, callback2));
passport.use(new LocalStrategy({ usernameField: "email" }, LocalStrategycallback));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((userId, done) => {
  authModel.findById(userId)
    .then((user) => {
      done(null, user);
    })
    .catch((err) => {
      done(err);
    });
});

module.exports = passport;
