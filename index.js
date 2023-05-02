require("./utils.js");

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * millis)

/* secret information section */ 
//process of env file
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    const buttons = `
        <button onclick="window.location.href='/signup'">Sign up</button>
        <button onclick="window.location.href='/login'">Log in</button>
      `;
    res.send(`<h1>Create an account or log in</h1>${buttons}`);
  } else {
    const buttons = `
        <button onclick="window.location.href='/members'">Go to Members Area</button>
        <button onclick="window.location.href='/logout'">Log out</button>
      `;
    res.send(`<h1>Hello, ${req.session.username}!</h1>${buttons}`);
  }
});

app.get("/nosql-injection", async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ email: 1, password: 1, username: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

app.get("/signUp", (req, res) => {
  var html = `
    <h2>Sign up :</h2>
    <form action='/submitUser' method='post'>
    Username:
    <input name='username' type='text' placeholder='Username'>
    <br>
    Email:
    <input name='email' type='text' placeholder='Email'>
    <br>
    Password:
    <input name='password' type='password' placeholder='Password'>
    <br><br>
    <button><a href="/" style="text-decoration: none; color:black;">Home</a></button>
    <button>Sign up</button>
    </form>
    `;
  res.send(html);
});

app.get("/login", (req, res) => {
  var html = `
    <h2>Log In</h2>
    <form action='/loggingin' method='post'>
    Email: <input name='email' type='text' placeholder='Email'>
    <br>
    Password: <input name='password' type='password' placeholder='Password'>
    <br><br>
    <button><a href="/" style="text-decoration: none; color:black;">Home</a></button>
    <button>Log-in</button>
    </form>
    `;
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  if (!username || !email || !password) {
    res.send(`All fields are required. <br><br>Please <a href='/signup'>try again</a>`);
    return;
  }

  //Joi to valudate user name
  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    password: Joi.string().max(20).required(),
    email: Joi.string().email().required(),
  });

  const validationResult = schema.validate({ username, password, email });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    var errorMessage = validationResult.error.details[0].message;
    res.send(`Error: ${errorMessage}. <br><br> Please <a href="/signup">try again</a>.`);
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    username: username,
    password: hashedPassword,
    email: email,
  });
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.username = username;
  req.session.cookie.maxAge = expireTime;

  res.redirect("/loggedin");
});

//JOI to validate input
app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(`Please fill out both email and password fields. <br><br> Please <a href='/login'>try again</a>.`);
    return;
  }

  //mongodb database
  const result = await userCollection
    .find({ email: email })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);
  if (result.length === 0) {
    res.send('Invalid email/password. <br><br> Please <a href="/login">try again</a>.');
    return;
  } else if (result.length != 1) {
    res.redirect("/login");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.email = email;
    req.session.username = result[0].username;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/loggedin");
    return;
  } else {
    res.send('Invalid email/password. <br><br> Please <a href="/login">try again</a>.');
    return;
  }
});

app.get("/loggedin", (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/members");
  } else {
    res.redirect("/");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/cat/:id", (req, res) => {
  var cat = req.params.id;

  if (cat == 1) {
    res.send("Dog1: <img src='/2.jpeg' style='width:250px;'>");
  } else if (cat == 2) {
    res.send("Dog2: <img src='/3.jpeg' style='width:250px;'>");
  } else if (cat == 3) {
    res.send("Dog3: <img src='/4.jpeg' style='width:250px;'>");
  } else {
    res.send("Invalid cat id: " + cat);
  }
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
  } else {
    const images = ["/2.jpeg", "/3.jpeg", "/4.jpeg.jpg"];
    randomIndex = Math.floor(Math.random() * images.length);
    res.send(`<h1>Hello, ${req.session.username}.</h1>
    <img src='${images[randomIndex]}' width= "250px">
    <form action='/logout' method='get'> 
      <br>
      <button type ='submit'>Log out</button>
    </form>`);
  }
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.send(
    '<img src = "/1.jpeg" width="250px"></img><br> <h2>Page not found - 404</h2>'
  );
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});