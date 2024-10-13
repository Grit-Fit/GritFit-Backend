const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { createClient } = require("@supabase/supabase-js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(
  cors({
    origin: "https://gritfit-ui.vercel.app",
  })
);

const JWT_SECRET = process.env.JWT_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_API_KEY = process.env.SUPABASE_API_KEY;

if (!SUPABASE_URL || !SUPABASE_API_KEY) {
  console.error("Supabase URL or API key is missing.");
  throw new Error(
    "Server configuration error: Supabase URL or API key is missing."
  );
}

const supabase = createClient(SUPABASE_URL, SUPABASE_API_KEY);
console.log("Supabase client created successfully");

//Just for testing Supabase connection //will remove later
supabase
  .from("userprofile")
  .select("*")
  .limit(1)
  .then(() => console.log("Successfully connected to Supabase"))
  .catch((error) => {
    console.error("Error connecting to Supabase:", error);
    console.error("Error details:", JSON.stringify(error, null, 2));
    throw new Error("Failed to connect to Supabase");
  });

// Home route
app.get("/", (req, res) => {
  res.send("Hello, this is the backend connected to Supabase!");
});

// Register user (create a new record in the userprofile table)
app.post("/api/createAccount", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    console.log("Attempting to create account for:", email);

    // Check if user already exists
    const { data: existingUsers, error: checkError } = await supabase
      .from("userprofile")
      .select("email")
      .eq("email", email);

    if (checkError) {
      console.error("Error checking existing user:", checkError);
      throw checkError;
    }

    if (existingUsers && existingUsers.length > 0) {
      console.log("User already exists:", email);
      return res.status(400).json({ message: "User already exists!" });
    }

    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    console.log("Inserting new user into database");

    // Add new user
    const { data: newUser, error } = await supabase
      .from("userprofile")
      .insert({ username, email, password: hashedPassword })
      .select()
      .single();

    if (error) {
      console.error("Error inserting new user:", error);
      throw error;
    }

    console.log("New user created successfully:", newUser.email);

    // Generate JWT token
    const token = jwt.sign({ id: newUser.id, email }, JWT_SECRET, {
      expiresIn: "1d",
    });

    return res
      .status(201)
      .json({ message: "User record added successfully!", token });
  } catch (error) {
    console.error("Error creating user:", error);
    console.error("Error details:", JSON.stringify(error, null, 2));
    res
      .status(500)
      .json({ message: "Error creating account", error: error.message });
  }
});

// Sign in user
app.post("/api/signIn", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Fetch user from database
    const { data: users, error } = await supabase
      .from("userprofile")
      .select("*")
      .eq("email", email);

    if (error) throw error;

    if (!users || users.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = users[0];

    // Check password
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "1d",
    });

    return res.status(200).json({ message: "Signed in successfully!", token });
  } catch (error) {
    console.error("Error signing in:", error);
    res.status(500).json({ message: "Error signing in", error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
