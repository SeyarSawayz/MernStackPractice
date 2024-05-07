const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const path = require("path");
const bcrypt = require("bcrypt");

const userModel = require("./models/user");
const postModel = require("./models/post");

const app = express();

app.set("view engine", "ejs");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(cookieParser());

const isLoggedin = (req, res, next) => {
  if (req.cookies.token === "") res.redirect("login");
  else {
    let data = jwt.verify(req.cookies.token, "secret");
    req.user = data;
    next();
  }
};

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  let { email, password } = req.body;

  let user = await userModel.findOne({ email });
  if (!user) return res.send("no user");
  bcrypt.compare(password, user.password, (err, result) => {
    if (result) res.redirect("profile");
    else res.send("email or password is wrong");
  });
  let token = jwt.sign({ email: email, userid: user._id }, "secret");
  res.cookie("token", token);
});

app.get("/logout", (req, res) => {
  res.cookie("token", "");
  res.redirect("/login");
});

app.post("/register", async (req, res) => {
  let { username, name, password, email, age } = req.body;
  let user = await userModel.findOne({ email });
  if (user) return res.status(500).send("user already registered");
  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(password, salt, async (err, hash) => {
      let user = await userModel.create({
        name,
        username,
        email,
        password: hash,
        age,
      });
      let token = jwt.sign({ email: email, userid: user._id }, "secret");
      res.cookie("token", token);
      res.send("registered");
    });
  });
});

app.get("/profile", isLoggedin, async (req, res) => {
  let user = await userModel
    .findOne({ email: req.user.email })
    .populate("posts");
  res.render("profile", { user });
});

app.post("/post", isLoggedin, async (req, res) => {
  let user = await userModel.findOne({ email: req.user.email });
  let { content } = req.body;

  let post = await postModel.create({
    user: user._id,
    content,
  });

  user.posts.push(post._id);
  await user.save();
  res.redirect("profile");
});

app.listen(3000);
