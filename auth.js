const passport = require("passport");
const { ObjectID } = require("mongodb");
const LocalStrategy = require("passport-local");
// handle encrypt password with hashing for storage in the database
const bcrypt = require("bcrypt");

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
};
