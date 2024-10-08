// backend/server.js
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(
  cors({
    origin: "https://gritfit-ui.vercel.app", // Replace with your actual Vercel frontend URL
  })
);

const JWT_SECRET = process.env.JWT_SECRET;

let users = [
  { username: "testuser", email: "test@example.com", password: "password123" },
  { username: "johnDoe", email: "john@example.com", password: "johnPassword" },
];

app.get("/", (req, res) => {
  res.send("Hello, this is the backend!");
});

//TODO: add exceptional handling like try catch blocks and proper logs
app.post("/api/createAccount", (req, res) => {
  const { username, email, password } = req.body;

  // Check if user already exists
  if (
    users.find((user) => user.username === username || user.email === email)
  ) {
    return res.status(400).json({ message: "User already exists!" });
  }

  const newUser = { username, email, password };
  users.push(newUser);

  const token = jwt.sign({ username: username, email: email }, JWT_SECRET, {
    expiresIn: "1d",
  });

  console.log("Users registered:", users);
  return res
    .status(201)
    .json({ message: "User record added successfully!", token });
});

app.post("/api/signIn", (req, res) => {
  const { email, password } = req.body;
  console.log("Sign-in attempt:", { email, password });

  const existingUser = users.find(
    (u) => u.email === email && u.password === password
  );

  if (existingUser) {
    console.log("Signed In Successfully");
    const token = jwt.sign(
      { username: existingUser.username, email: existingUser.email },
      JWT_SECRET,
      { expiresIn: "1d" }
    );
    return res
      .status(201)
      .json({ message: "User signed in successfully!", token });
  } else {
    console.log("Sign-in result:", "Failure");
    return res.status(401).json({
      message:
        "Invalid Username or Password, Please create an account if not registered.",
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
