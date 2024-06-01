const passport = require("passport");
// handle encrypt password with hashing for storage in the database
const bcrypt = require("bcrypt");

module.exports = function (app, myDataBase) {
  app.route("/").get((req, res) => {
    res.render("index", {
      title: "Connected to database",
      message: "Please log in",
      showLogin: true,
      showRegistration: true,
      showSocialAuth: true,
    });
  });
  // route to login will authenticate credentials on database stored user table
  app
    .route("/login")
    .post(
      passport.authenticate("local", { failureRedirect: "/" }),
      (req, res) => {
        res.redirect("/profile");
      }
    );
  app.route("/auth/github").get(passport.authenticate("github"));

  app
    .route("/auth/github/callback")
    .get(
      passport.authenticate("github", { failureRedirect: "/" }),
      (req, res) => {
        res.redirect("/profile");
      }
    );
  // route to show profile, will authenticate the current user to make sure they are that user
  // then will render the pug file based on that user
  app.route("/profile").get(ensureAuthenticated, (req, res) => {
    res.render("profile", { username: req.user.username });
  });

  // logs out the user with passport, then redirects them to the homepage
  app.route("/logout").get((req, res) => {
    req.logout();
    res.redirect("/");
  });

  // 1. Register the new user
  // 2. Authenticate the new user
  // 3. Redirect to /profile
  app.route("/register").post(
    (req, res, next) => {
      // encrypt usename with hash
      const hash = bcrypt.hashSync(req.body.password, 12);
      // Query database with findOne
      myDataBase.findOne({ username: req.body.username }, (err, user) => {
        // If there is an error, call next with the error
        if (err) {
          next(err);
        }
        // If a user is returned, redirect back to home
        else if (user) {
          res.redirect("/");
        }
        // If a user is not found and no errors occur, then insertOne into the database with the username and password.
        else {
          myDataBase.insertOne(
            {
              username: req.body.username,
              password: hash,
            },
            (err, doc) => {
              // if there is an error, redirect to home
              if (err) {
                res.redirect("/");
              }
              // As long as no errors occur there, call next to authenticate the user
              else {
                // The inserted document is held within
                // the ops property of the doc
                next(null, doc.ops[0]);
              }
            }
          );
        }
      });
    },
    passport.authenticate("local", { failureRedirect: "/" }),
    (req, res, next) => {
      res.redirect("/profile");
    }
  );

  // page/route not found 404 handling
  // needs to be after all other routes
  app.use((req, res, next) => {
    res.status(404).type("text").send("Not Found");
  });
};
// uses isAuthenticated to check if a user is correctly authenticated
// I think this uses some amount of local storage with the serialized id to tell
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/");
}
