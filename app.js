require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose")
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate")

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: "Our little secret",
    resave: false, 
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGO_DB)

const userSchema = new mongoose.Schema({
    email: String, 
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done){
    done(null, user.id);
});
passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://secretappid.herokuapp.com/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user); 
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "https://secretappid.herokuapp.com/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
    res.render("home"); 
});

//////////  GOOGLE AUTH  /////////
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
});

//////////  FACEBOOK AUTH  /////////
app.get("/auth/facebook",
  passport.authenticate("facebook")
);

app.get("/auth/facebook/secrets", 
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
});

app.get("/secrets", function(req, res){
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
        if (err) {
            console.log(err);
        } else {
            if (foundUsers){
                res.render("secrets", {userWithSecrets: foundUsers})
            };
        };
    });
});

app.route("/submit")
    .get(function(req, res){
        if(req.isAuthenticated()){
            res.render("submit")
        } else {
            res.redirect("/login")
        }
    })

    .post(function(req, res){
        const submittedSecret = req.body.secret;

        User.findById(req.user.id, function(err, foundUser){
            if(err){
                console.log(err);
            } else {
                if(foundUser) {
                    foundUser.secret = submittedSecret;
                    foundUser.save(function(){
                        res.redirect("/secrets");
                    })
                }
            }
        })
    });
;

app.route("/login")
    .get(function(req, res){
        res.render("login");
    })

    .post(function(req, res){
        const user = new User({
            username: req.body.username,
            password: req.body.password
          });
        
          req.login(user, function(err){
            if (err) {
              console.log(err);
              res.redirect("/login");
            } else {
              passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
              });
            }
          });
    });
;

app.route("/register")
    .get(function(req, res){
        res.render("register");
    })

    .post(function(req, res){
        User.register({username: req.body.username}, req.body.password, function(err, user){
            if (err) {
              console.log(err);
              res.redirect("/register");
            } else {
              passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
              });
            }
        });
    });
;

app.get("/logout", function(req, res, next) {
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect('/');
    });
});


let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function() {
  console.log("Server started!");
});