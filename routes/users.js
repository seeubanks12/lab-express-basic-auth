var express = require("express");
const req = require("express/lib/request");
var router = express.Router();
const bcrypt = require("bcrypt");
const User = require("../models/User.model");
const { get } = require("express/lib/response");
const saltRounds = 10;

//Add GET router for username

router.get("/signup", function (req, res, next) {
  res.render("signup", { title: "Sign Up Page" });
});

router.post("/signup", function (req, res, next) {
  //error messages is users do not input information. This sends a message to block the information.
  let errors = [];

  if (!req.body.username) {
    errors.push("You did not include a username!");
  }
  if (!req.body.password) {
    errors.push("You need a password!");
  }
  if (errors.length > 0) {
    res.render(errors);
  }

  //hash the password
  const salt = bcrypt.genSaltSync(saltRounds);
  const hashedPass = bcrypt.hashSync(req.body.password, salt);

  //User create for post method

  User.create({
    username: req.body.username,
    password: hashedPass,
  })
    .then((createdUser) => {
      console.log("User was created", createdUser);

      //add session here
      console.log(req.session);
      req.session.user = createdUser;
      console.log(req.session.user);
      res.redirect("/");
    })
    .catch((err) => {
      console.log("Something went wrong", err.errors);
      res.render(err);
    });
});

router.get("/login", (req, res) => {
  res.render("login");
})

router.post("/login", (req, res) => {
  //Make sure all fields have content
  let errors = [];

  if (!req.body.username) {
    errors.push("You did not include a username!");
  }
  if (!req.body.password) {
    errors.push("You need a password!");
  }
  if (errors.length > 0) { 
    res.render(errors);
  }

  //Verify username and password

  User.findOne({ username: req.body.username })
    .then((foundUser) => {
      //Case 1. user does not exist
      //Solution: send a message back to user
      if (!foundUser) {
        res.render("Username not found");
      }

      //Case 2: username is found
      //Solution: Check the password

      const match = bcrypt.compareSync(req.body.password, foundUser.password);

      //Case 2.5 Passwords don't match
      //Solution: send message back to user

      if (!match) {
        res.render("Incorrect password");
      }

      //Case 3: Username and password are correct
      //Solution: Create a session for the logged in user

      req.session.user = foundUser;
      console.log("Welcome to the website");
      res.render("homepage")
    })
    .catch((err) => {
      console.log("Something went wrong", err);
      res.render("homepage");
    });
});

router.get("/logout", (req, res) => {
  req.session.destroy();
  console.log("This is the session", req.session);
  res.json("you have logged out");
});

module.exports = router;
