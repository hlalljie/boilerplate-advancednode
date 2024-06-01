const passport = require("passport");
const { ObjectID } = require("mongodb");
const LocalStrategy = require("passport-local");
// handle encrypt password with hashing for storage in the database
const bcrypt = require("bcrypt");

const GitHubStrategy = require("passport-github").Strategy;

module.exports = function (app, myDataBase) {
  // serializes the user_id so that it can be stored securely in the database
  passport.serializeUser((user, done) => {
    done(null, user._id);
  });
  // deserializes user_id and retrieves it from the database
  passport.deserializeUser((id, done) => {
    myDataBase.findOne({ _id: new ObjectID(id) }, (err, doc) => {
      done(null, doc);
    });
  });

  // defines a strategy to authenticate user info in the database
  passport.use(
    new LocalStrategy((username, password, done) => {
      myDataBase.findOne({ username: username }, (err, user) => {
        console.log(`User ${username} attempted to log in.`);
        if (err) return done(err);
        if (!user) return done(null, false);
        // check if encrypted password hashes to the right value in the database
        if (!bcrypt.compareSync(password, user.password)) {
          return done(null, false);
        }
        return done(null, user);
      });
    })
  );

  //defines the strategy to authenticate via github sign in (OAth 2.0)
  passport.use(
    new GitHubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL:
          "https://3000-tan-coral-fjts6u5h8gx.ws-us114.gitpod.io/auth/github/callback",
      },
      function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        myDataBase.findOneAndUpdate(
          { id: profile.id },
          {
            $setOnInsert: {
              id: profile.id,
              username: profile.username,
              name: profile.displayName || "John Doe",
              photo: profile.photos[0].value || "",
              email: Array.isArray(profile.emails)
                ? profile.emails[0].value
                : "No public email",
              created_on: new Date(),
              provider: profile.provider || "",
            },
            $set: {
              last_login: new Date(),
            },
            $inc: {
              login_count: 1,
            },
          },
          { upsert: true, new: true },
          (err, doc) => {
            return cb(null, doc.value);
          }
        );
      }
    )
  );
};
