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
  const { email, password } = req.body;

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
      .insert({ email, password: hashedPassword })
      .select()
      .single();

    if (error) {
      console.error("Error inserting new user:", error);
      throw error;
    }

    if (!newUser) {
      throw new Error("User created but not returned from database");
    }

    console.log("New user created successfully:", newUser.email);

    // Generate JWT token
    const token = jwt.sign({ id: newUser.id, email }, JWT_SECRET, {
      //from where is it getting the id???
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

app.post("/api/updateUsername", async (req, res) => {
  const { newUsername } = req.body;
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    // Verify the token
    const decoded = jwt.verify(token, JWT_SECRET);

    // The email is available in the decoded token
    const email = decoded.email;

    // Update the username in the database using email
    const { data, error } = await supabase
      .from("userprofile")
      .update({ username: newUsername })
      .eq("email", email);

    if (error) throw error;

    return res.status(200).json({ message: "Username updated successfully" });
  } catch (error) {
    console.error("Error updating username:", error);
    res
      .status(500)
      .json({ message: "Error updating username", error: error.message });
  }
});

app.post("/api/userprogressStart", async (req, res) => {
  const authHeader = req.headers.authorization;
  console.log("authHeader", authHeader);
  if (!authHeader) {
    return res.status(401).json({ message: "user not authenticated" });
  }
  // const token = authHeader.split(" ")[1];
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({
      message: "Authorization header must be in format: Bearer <token>",
    });
  }

  const token = parts[1];
  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  const { taskId } = req.body;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.id;
    if (!taskId) {
      return res.status(400).json({ message: "Task ID is required" });
    }
    console.log(
      "userprogess api called to start the task for userid: " +
        userId +
        "for task: " +
        taskId
    );
    const { data: existingProgress, error: checkError } = await supabase
      .from("userprogress")
      .select("*")
      .eq("userid", userId)
      .eq("taskid", taskId)
      .single();

    if (checkError && checkError.code !== "PGRST116") {
      // PGRST116 is the error code for no rows returned
      throw checkError;
    }

    if (existingProgress) {
      return res
        .status(409)
        .json({ message: "Progress entry already exists for this task" });
    }

    const { data, error } = await supabase
      .from("userprogress")
      .insert({ taskid: taskId, userid: userId, taskstatus: "InProgress" })
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({
      message: "User progress start saved successfully",
      data: data,
    });
  } catch (error) {
    res.status(error.status || 500).json({
      message: "Error updating userProgress",
      error: error.message,
    });
  }
});

app.post("/api/userprogressNC", async (req, res) => {
  //not completion of the task
  //firstly checking the authentication
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "user not authenticated" }); //to be returned or not??
  }
  const { taskId, rsn } = req.body; //we are using object destructuring here.. this is same as const taskId = req.body.taskid;
  if (!taskId || !rsn) {
    return res
      .status(400)
      .json({ message: "required details missing from req body" });
  }
  //splitting the authHeader to get the bearer token
  try {
    const token = authHeader.split(" ")[1]; //splitting the authtoken to get the token.. also there can be times when we do not have the token
    const decoded = jwt.verify(token, JWT_SECRET); //sending the signature and the token to check if it has the right user, email and the iat or issues time so checks the expiry too
    const userId = decoded.id;
    //first checking if the record exists
    const { data: existingData, error: checkError } = await supabase
      .from("userprogress")
      .select("*")
      .eq("userid", userId)
      .eq("taskid", taskId)
      .single();

    // Better error handling
    if (checkError && checkError?.code !== "PGRST116") {
      //this may give null ptr if checkptr isnt present.. so adding optional parameter
      throw checkError;
    }

    if (!existingData) {
      return res.status(404).json({
        message: "No progress entry found for this task",
      });
    }
    const { data: updateData, error: updateError } = await supabase
      .from("userprogress")
      .update({
        taskstatus: "Not Completed",
        completion_date: new Date().toISOString(),
        notcompletionreason: rsn,
      })
      .eq("taskid", taskId)
      .eq("userid", userId)
      .select()
      .single();

    if (updateError) {
      throw updateError;
    }
    return res.status(201).json({
      message: "User progress start saved successfully",
      data: updateData,
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      message: "Error updating userProgress",
      error: error.message,
    });
  }
});

app.post("/api/userprogressC", async (req, res) => {
  // completion of the task
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "token header not present" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.id;
    const { taskId } = req.body;
    const { data: existingData, error: checkError } = await supabase
      .from("userprogress")
      .select("*")
      .eq("userid", userId)
      .eq("taskid", taskId)
      .single();

    if (checkError) {
      console.log("Check Error:", checkError);
      return res.status(404).json({
        message: "Error checking user progress",
        error: checkError.message,
      });
    }

    // If no record exists
    if (!existingData) {
      return res.status(404).json({
        message: "No user progress record found to update",
      });
    }

    const { data: updateData, error: updateError } = await supabase
      .from("userprogress")
      .update({
        taskstatus: "Completed",
        completion_date: new Date().toISOString(),
      })
      .eq("taskid", taskId)
      .eq("userid", userId)
      .select()
      .single();

    if (updateError) {
      throw updateError;
    }
    return res.status(201).json({
      message: "User progress start saved successfully",
      data: updateData,
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      message: "Error updating userProgress",
      error: error.message,
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
