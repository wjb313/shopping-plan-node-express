const express = require("express");
const path = require("path");
const redis = require("redis");
const bcrypt = require("bcrypt");
const session = require("express-session");
const favicon = require("serve-favicon");
const { resolve } = require("path");

const app = express();
const client = redis.createClient();

const RedisStore = require("connect-redis")(session);

app.use("/static", express.static("./static/"));

// middleware to parse urlencoded username and password information
app.use(express.urlencoded({ extended: true }));

// middleware to parse urlencoded username and password information
app.use(express.json());

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
app.use(favicon(path.join(__dirname, "/static/icons", "favicon.ico")));

// setup Pug templating engine; configure to point to the 'views' folder
app.set("view engine", "pug");
app.set("views", path.join(__dirname, "views"));

// check for user session; direct to dinner plan page if session exists
app.get("/", (req, res) => {
  if (req.session.userid) {
    res.render("dashboard");
  } else {
    res.render("login");
  }
});

// handle sign up/sign in
app.post("/", (req, res) => {
  const { username, password } = req.body;
  console.log(req.body);
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
    res.render("dashboard");
  };

  // function to handle new user signup
  const handleSignup = (username, password) => {
    client.select(15, function (err, res) {
      client.incr("userid", async (err, userid) => {
        client.hset("users", username, userid);

        const saltRounds = 10;
        const hash = await bcrypt.hash(password, saltRounds);

        client.hset(`user:${userid}`, "hash", hash, "username", username);

        saveSessionAndRenderDashboard(userid);
      });
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
  client.select(15, function (err, res) {
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
});

// nav to dinner plan
app.get("/dinnerplan", (req, res) => {
  if (req.session.userid) {
    const currentUserId = req.session.userid;
    console.log(currentUserId);
    client.select(14, function () {
      client.hgetall(`dotw:${currentUserId}`, (err, currentUserDOTW) => {
        console.log("This is the current user ID: " + `dotw:${currentUserId}`);
        console.log("This is the current user DOTW order: " + currentUserDOTW);
        res.render("dinnerplan", { currentUserDOTW });
      });
    });
  } else {
    res.render("login");
  }
});

// nav to shopping list
app.get("/shoppinglist", (req, res) => {
  if (req.session.userid) {
    res.render("shoppinglist");
  } else {
    res.render("login");
  }
});

// nav to dinner plan
app.get("/dashboard", (req, res) => {
  if (req.session.userid) {
    res.render("dashboard");
  } else {
    res.render("login");
  }
});

// nav to shopping list
app.get("/logout", (req, res) => {
  if (req.session.userid) {
    res.render("logout");
  } else {
    res.render("login");
  }
});

app.get("/loggedout", (req, res) => {
  req.session.destroy();
  res.render("loggedout");
});

// EVERYTHING BELOW HERE IS TEST SCRIPT //

// handle dotw order
app.post("/dotw", (req, res) => {
  const daysArray = req.body;
  const currentUserId = req.session.userid;

  //const currentUserDOTW = console.log(currentUserId);
  console.dir("This is what came over " + daysArray[0]);

  //client.hset(`user:${userid}`, "hash", hash, "username", username);

  client.select(14, function (err, res) {
    client.hset(
      `dotw:${currentUserId}`,
      "day1",
      daysArray[0],
      "day2",
      daysArray[1],
      "day3",
      daysArray[2],
      "day4",
      daysArray[3],
      "day5",
      daysArray[4],
      "day6",
      daysArray[5],
      "day7",
      daysArray[6]
    );
  });
});

// web server
app.listen(3000, () => console.log("Server ready"));
