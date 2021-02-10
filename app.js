const express = require("express");
const path = require("path");
const redis = require("redis");
const bcrypt = require("bcrypt");
const session = require("express-session");
const favicon = require("serve-favicon");

const app = express();
const client = redis.createClient();

const RedisStore = require("connect-redis")(session);

// middleware to parse urlencoded username and password information
app.use(express.urlencoded({ extended: true }));

// middleware to manage user sessions via redis
app.use(
  session({
    store: new RedisStore({ client: client }),
    resave: true,
    saveUninitialized: true,
    cookie: {
      maxAge: 36000000, //10 hours, in milliseconds
      httpOnly: false,
      secure: false,
    },
    secret: "bM80SARMxlq4fiWhulfNSeUFURWLTY8vyf",
  })
);

// configure favicon for the site
app.use(favicon(path.join(__dirname, "icons", "favicon.ico")));

// setup Pug templating engine; configure to point to the 'views' folder
app.set("view engine", "pug");
app.set("views", path.join(__dirname, "views"));

// check for user session; direct to dinner plan page if session exists
app.get("/", (req, res) => {
  if (req.session.userid) {
    res.render("dinnerplan");
  } else {
    res.render("login");
  }
});

// handle sign up/sign in
app.post("/", (req, res) => {
  const { username, password } = req.body;

  // send to error page if username or password is left blank
  if (!username || !password) {
    res.render("error", {
      message: "Please set both username and password",
    });
    return;
  }

  // function to save a newly established session and direct to dinner plan page
  const saveSessionAndRenderDashboard = (userid) => {
    req.session.userid = userid;
    req.session.save();
    res.render("dinnerplan");
  };

  // function to handle new user signup
  const handleSignup = (username, password) => {
    client.incr("userid", async (err, userid) => {
      client.hset("users", username, userid);

      const saltRounds = 10;
      const hash = await bcrypt.hash(password, saltRounds);

      client.hset(`user:${userid}`, "hash", hash, "username", username);

      saveSessionAndRenderDashboard(userid);
    });
  };

  // function to handle existing user login
  const handleLogin = (userid, password) => {
    client.hget(`user:${userid}`, "hash", async (err, hash) => {
      const result = await bcrypt.compare(password, hash);
      if (result) {
        saveSessionAndRenderDashboard(userid);
      } else {
        res.render("error", {
          message: "Incorrect password",
        });
        return;
      }
    });
  };

  // call to redis to see if the username exists
  client.hget("users", username, (err, userid) => {
    if (!userid) {
      // signup process - increment userid (number) and set the username
      handleSignup(username, password);
    } else {
      //login process - check password hash and login if correct, error page if incorrect
      handleLogin(userid, password);
    }
  });
});

// web server
app.listen(3000, () => console.log("Server ready"));
