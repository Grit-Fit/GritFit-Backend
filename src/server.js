const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { createClient } = require("@supabase/supabase-js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
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

// Helper function to generate tokens
const generateTokens = (payload) => {
  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "1d" }); // Short-lived access token
  const refreshToken = jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: "30d",
  }); // Long-lived refresh token
  return { accessToken, refreshToken };
};

// Middleware to verify access tokens
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Authorization header missing" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// Home route
app.get("/", (req, res) => {
  res.send("Hello, this is the backend connected to Supabase!");
});

// Refresh token endpoint
app.post("/api/refreshToken", (req, res) => {
  const { refreshToken } = req.cookies;
  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token provided" });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const tokens = generateTokens({ id: decoded.userid, email: decoded.email });

    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    });

    return res.status(200).json({ accessToken: tokens.accessToken });
  } catch (error) {
    return res
      .status(401)
      .json({ message: "Invalid or expired refresh token" });
  }
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
      .insert({
        email,
        password: hashedPassword,
        created_at: new Date().toISOString(),
      })
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
    const tokens = generateTokens({ id: newUser.userid, email });
    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    });

    return res.status(201).json({
      message: "User created successfully!",
      token: tokens.accessToken,
    });
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

    // Generate JWT tokens
    const tokens = generateTokens({ id: user.userid, email: user.email });
    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    });

    return res
      .status(200)
      .json({ message: "Signed in successfully!", token: tokens.accessToken });
  } catch (error) {
    console.error("Error signing in:", error);
    res.status(500).json({ message: "Error signing in", error: error.message });
  }
});

app.post("/api/updateUsername", verifyToken, async (req, res) => {
  const { newUsername } = req.body;

  try {
    // Verify the token
    const email = req.user.email;

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

app.post("/api/getTaskData", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // First, get the taskdetailsid from taskdetails table
    const { data: taskDetails, error: taskError } = await supabase
      .from("taskdetails")
      .select("*");
    if (taskError || !taskDetails) {
      console.log("Task Details Error:", taskError);
      return res.status(404).json({
        message: "Task details not found",
        error: taskError?.message,
      });
    }
    // console.log("Task Details: ", taskDetails);
    let taskDetailIds = [];
    for (const taskDetail of taskDetails) {
      taskDetailIds.push(parseInt(taskDetail.taskdetailsid));
    }

    // Convert taskdetailsid to number to ensure proper type
    // console.log("Task Details: ", taskDetailIds);
    // Check if there's an existing progress record
    // const supauser = supabase.auth.user();
    // console.log("Authenticated User:", supauser);
    //first checking if the record exists
    const { data: progressData, error: checkError } = await supabase
      .from("userprogress")
      .select("*")
      .eq("userid", userId)
      .in("taskdetailsid", taskDetailIds)
      .order("created_at", { ascending: false });
    // Better error handling
    if (checkError && checkError?.code !== "PGRST116") {
      //this may give null ptr if checkptr isnt present.. so adding optional parameter
      throw checkError;
    }

    if (!progressData) {
      return res.status(404).json({
        message: "No progress entry found for this task",
      });
    }

    const existingData = Object.values(
      progressData.reduce((acc, record) => {
        const key = `${record.taskdetailsid}-${record.phaseid}`;
        if (!acc[key]) {
          acc[key] = record; // Take the first (most recent) record per group
        }
        return acc;
      }, {})
    );
    const mergedData = taskDetails.map((task) => {
      // Find the corresponding progress data for the current task
      const userProgress = existingData.find(
        (progress) => progress.taskdetailsid === task.taskdetailsid
      );
      return {
        taskid: task.taskid,
        taskdetailsid: task.taskdetailsid,
        lastswipedat: userProgress ? userProgress.completion_date : null,
        phaseid: task.phaseid,
        taskstatus: userProgress ? userProgress.taskstatus : "Not Started",
        nutritiontheory: task.nutritiontheory,
        taskdesc: task.taskdesc,
      };
    });

    console.log("User Progress Data: ", mergedData);
    if (mergedData) {
      return res.status(201).json({
        message: "Task Data with user progress track retrieved successfully.",
        data: mergedData,
      });
    } else {
      return res.status(201).json({
        message: "Task Data with user progress track retrieved successfully.",
        data: null,
      });
    }
  } catch (error) {
    return res.status(error.status || 500).json({
      message: "Error retrieving the taskData.",
      error: error.message,
    });
  }
});

app.post("/api/userprogressStart", verifyToken, async (req, res) => {
  const { phaseId, taskId } = req.body;

  try {
    const userId = req.user.id;
    if (!taskId || !phaseId) {
      return res
        .status(400)
        .json({ message: "Required information is missing." });
    }
    console.log(
      "userprogess api called to start the task for userid: " +
        userId +
        "for task: " +
        taskId
    );
    const { data: taskDetails, error: taskError } = await supabase
      .from("taskdetails")
      .select("taskdetailsid")
      .eq("phaseid", phaseId)
      .eq("taskid", taskId)
      .single();

    if (taskError || !taskDetails) {
      console.log("Task Details Error:", taskError);
      return res.status(404).json({
        message: "Task details not found",
        error: taskError?.message,
      });
    }

    // Convert taskdetailsid to number to ensure proper type
    const taskDetailsId = parseInt(taskDetails.taskdetailsid);
    console.log("Task Details: ", taskDetailsId);
    if (isNaN(taskDetailsId)) {
      return res.status(400).json({
        message: "Invalid taskdetailsid",
      });
    }

    const { data: existingProgress, error: checkError } = await supabase
      .from("userprogress")
      .select("*")
      .eq("userid", userId)
      .eq("taskdetailsid", taskDetailsId)
      .eq("taskstatus", "In Progress");

    if (checkError && checkError.code !== "PGRST116") {
      // PGRST116 is the error code for no rows returned
      throw checkError;
    }

    if (existingProgress.length !== 0) {
      return res
        .status(409)
        .json({ message: "Progress entry already exists for this task" });
    } else {
      const { data, error } = await supabase
        .from("userprogress")
        .insert({
          taskdetailsid: taskDetailsId,
          userid: userId,
          taskstatus: "In Progress",
          created_at: new Date().toLocaleString(),
        })
        .select()
        .single();

      if (error) throw error;

      res.status(201).json({
        message: "User progress start saved successfully",
        data: data,
      });
    }
  } catch (error) {
    res.status(error.status || 500).json({
      message: "Error creating userProgress",
      error: error.message,
    });
  }
});

app.post("/api/userprogressNC", verifyToken, async (req, res) => {
  //not completion of the task
  const { phaseId, taskId, reasonForNonCompletion, failedGoal } = req.body; //we are using object destructuring here.. this is same as const taskId = req.body.taskid;
  if (!taskId || !reasonForNonCompletion) {
    return res
      .status(400)
      .json({ message: "required details missing from req body" });
  }
  //splitting the authHeader to get the bearer token
  try {
    const userId = req.user.id;
    console.log("Looking up task details with:", {
      phaseId,
      taskId,
    });

    // First, get the taskdetailsid from taskdetails table
    const { data: taskDetails, error: taskError } = await supabase
      .from("taskdetails")
      .select("taskdetailsid")
      .eq("phaseid", phaseId)
      .eq("taskid", taskId)
      .single();

    if (taskError || !taskDetails) {
      console.log("Task Details Error:", taskError);
      return res.status(404).json({
        message: "Task details not found",
        error: taskError?.message,
      });
    }

    // Convert taskdetailsid to number to ensure proper type
    const taskDetailsId = parseInt(taskDetails.taskdetailsid);
    console.log("Task Details: ", taskDetailsId);
    if (isNaN(taskDetailsId)) {
      return res.status(400).json({
        message: "Invalid taskdetailsid",
      });
    }

    // Check if there's an existing progress record
    // const supauser = supabase.auth.user();
    // console.log("Authenticated User:", supauser);
    //first checking if the record exists
    const { data: existingData, error: checkError } = await supabase
      .from("userprogress")
      .select("*")
      .eq("userid", userId)
      .eq("taskdetailsid", taskDetailsId)
      .eq("taskstatus", "In Progress")
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
    const dataToUpdate = {
      taskstatus: "Not Completed",
      completion_date: new Date().toLocaleString(),
      notcompletionreason: reasonForNonCompletion,
    };

    // Include failedGoal if phaseId === 3
    if (phaseId === 3) {
      if (!failedGoal) {
        return res.status(400).json({
          message: "Failed goal is required for phase 3",
        });
      }
      dataToUpdate.whichgoal = failedGoal;
    }
    const { data: updateData, error: updateError } = await supabase
      .from("userprogress")
      .update(dataToUpdate)
      .eq("taskdetailsid", taskDetailsId)
      .eq("userid", userId)
      .eq("taskstatus", "In Progress")
      .select()
      .single();

    if (updateError) {
      throw updateError;
    }
    return res.status(201).json({
      message: "User progress non completion saved successfully",
      data: updateData,
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      message: "Error updating userProgress",
      error: error.message,
    });
  }
});

app.post("/api/userprogressC", verifyToken, async (req, res) => {
  console.log("userprogressC started");
  try {
    const userId = req.user.id;
    const { phaseId, taskId, nutritiontheory } = req.body;

    console.log("Looking up task details with:", {
      phaseId,
      taskId,
      nutritiontheory,
    });

    // First, get the taskdetailsid from taskdetails table
    const { data: taskDetails, error: taskError } = await supabase
      .from("taskdetails")
      .select("taskdetailsid")
      .eq("phaseid", phaseId)
      .eq("taskid", taskId)
      .eq("nutritiontheory", nutritiontheory)
      .single();

    if (taskError || !taskDetails) {
      console.log("Task Details Error:", taskError);
      return res.status(404).json({
        message: "Task details not found",
        error: taskError?.message,
      });
    }

    // Convert taskdetailsid to number to ensure proper type
    const taskDetailsId = parseInt(taskDetails.taskdetailsid);
    console.log("Task Details: ", taskDetailsId);
    if (isNaN(taskDetailsId)) {
      return res.status(400).json({
        message: "Invalid taskdetailsid",
      });
    }

    // Check if there's an existing progress record
    // const supauser = supabase.auth.user();
    // console.log("Authenticated User:", supauser);
    const { data: existingData, error: checkError } = await supabase
      .from("userprogress")
      .select("*")
      .eq("userid", userId)
      .eq("taskdetailsid", taskDetailsId)
      .eq("taskstatus", "In Progress")
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
      return res.status(400).json({
        message: "User progress not present or not started yet",
      });
    }

    // If record exists but is already completed, return error
    if (existingData.taskstatus !== "In Progress") {
      return res.status(400).json({
        message: "Task is already completed",
        data: existingData,
      });
    }

    // Update existing record only if not completed
    const { data: updateData, error: updateError } = await supabase
      .from("userprogress")
      .update({
        taskstatus: "Completed",
        completion_date: new Date().toLocaleString(),
      })
      .eq("taskdetailsid", taskDetailsId)
      .eq("userid", userId)
      .eq("taskstatus", "In Progress")
      .select()
      .single();

    if (updateError) {
      throw updateError;
    }

    return res.status(200).json({
      message: "User progress updated successfully",
      data: updateData,
    });
  } catch (error) {
    console.error("Error in userprogressC:", error);
    return res.status(error.status || 500).json({
      message: "Error updating userProgress",
      error: error.message,
    });
  }
});

// Logout endpoint
app.post("/api/logout", (req, res) => {
  res.clearCookie("refreshToken");
  res.status(200).json({ message: "Logged out successfully" });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
