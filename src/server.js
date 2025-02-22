const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { createClient } = require("@supabase/supabase-js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5050;

app.use(express.json());
app.use(cookieParser());

const allowedOrigins = ["https://www.gritfit.site", "http://localhost:3000"];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("CORS Not Allowed"));
      }
    },
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
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

const supabase = createClient(SUPABASE_URL, SUPABASE_API_KEY, { schema: "public" });
console.log("Supabase client created successfully");

(async () => {
  try {
   
    await supabase.rpc("pg_reload_conf");
    console.log("Supabase schema cache refreshed");

   
    const { data: columns, error: columnError } = await supabase
      .from("userprogress")
      .select("task_activation_date")
      .limit(1);

    if (columnError) {
      console.error("Error checking column:", columnError);
    } else {
      console.log("Column exists in the database");
    }
  } catch (err) {
    console.error("Error during Supabase setup:", err);
  }
})();

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


const generateTokens = (payload) => {
  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "1d" });
  const refreshToken = jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: "30d",
  });
  return { accessToken, refreshToken };
};


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


app.get("/", (req, res) => {
  res.send("Hello, this is the backend connected to Supabase!");
});


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
    return res.status(401).json({ message: "Invalid or expired refresh token" });
  }
});


app.post("/api/createAccount", async (req, res) => {
  const { email, password } = req.body;

  try {
    console.log("Attempting to create account for:", email);


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

   
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

   
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


app.post("/api/updateTaskStatus", verifyToken, async (req, res) => {
  const { taskId, phaseId, status } = req.body;
  const userId = req.user.id;

  try {
    const { data: taskDetails } = await supabase
      .from("taskdetails")
      .select("taskdetailsid")
      .eq("phaseid", phaseId)
      .eq("taskid", taskId)
      .single();

    const { error: updateError } = await supabase
      .from("userprogress")
      .update({ taskstatus: status })
      .eq("taskdetailsid", taskDetails.taskdetailsid)
      .eq("userid", userId);

    if (updateError) throw updateError;

    res.status(200).json({ message: "Task status updated successfully" });
  } catch (error) {
    res.status(500).json({
      message: "Error updating task status",
      error: error.message,
    });
  }
});

// Update username
app.post("/api/updateUsername", verifyToken, async (req, res) => {
  const { newUsername } = req.body;

  try {
    const email = req.user.email;

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

app.get("/api/getUserProfile", verifyToken, async (req, res) => {
  try {
    const email = req.user.email; // from the JWT via verifyToken
    const { data, error } = await supabase
      .from("userprofile")
      .select("username")
      .eq("email", email)
      .single();

    if (error) {
      console.error("Error fetching user profile:", error);
      return res.status(500).json({ message: "Failed to fetch user profile" });
    }

    if (!data) {
      return res.status(404).json({ message: "User not found" });
    }

    // Return the username
    return res.status(200).json({ username: data.username });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: err.message });
  }
});



app.post("/api/getUserProgress", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { data: userProgressData, error: checkError } = await supabase
      .from("userprogress")
      .select("*")
      .eq("userid", userId)
      .order("created_at", { ascending: false });

   
    if (checkError && checkError?.code !== "PGRST116") {
      throw checkError;
    }

   
    if (!userProgressData || userProgressData.length === 0) {
      return res.status(404).json({
        message: "No progress entry found for this user",
      });
    }

    return res.status(200).json({
      message: "User Progress Data retrieved successfully",
      data: userProgressData,
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      message: "Error retrieving the taskData.",
      error: error.message,
    });
  }
});


app.post("/api/getTaskData", verifyToken, async (req, res) => {
  console.log("[getTaskData] Fetching task data for user...");
  const userId = req.user.id;

  try {
    const { data: taskDetails, error: taskDetailsError } = await supabase
      .from("taskdetails")
      .select("*");

    if (taskDetailsError || !taskDetails) {
      console.error("[getTaskData] Error fetching task details:", taskDetailsError);
      return res.status(404).json({ message: "Task details not found" });
    }

    const taskDetailIds = taskDetails.map(task => parseInt(task.taskdetailsid));

    const { data: userProgress, error: userProgressError } = await supabase
      .from("userprogress")
      .select("taskdetailsid, completion_date, taskstatus, task_activation_date")
      .eq("userid", userId)
      .in("taskdetailsid", taskDetailIds)
      .order("created_at", { ascending: false });

    if (userProgressError && userProgressError?.code !== "PGRST116") {
      console.error("[getTaskData] Error fetching user progress:", userProgressError);
      throw userProgressError;
    }

    console.log("[getTaskData] Retrieved user progress data:", userProgress);

    
const now = new Date();

const existingData = userProgress.reduce((acc, record) => {
  const recordActivation = new Date(record.task_activation_date);

  if (!acc[record.taskdetailsid]) {
    acc[record.taskdetailsid] = record;
  } else {
    const stored = acc[record.taskdetailsid];
    const storedActivation = new Date(stored.task_activation_date);

    // Check if both records are now "active"
    const recordIsActive = recordActivation <= now;
    const storedIsActive = storedActivation <= now;

    if (recordIsActive && storedIsActive) {
     
      const recordCreated = new Date(record.created_at);
      const storedCreated = new Date(stored.created_at);

      if (recordCreated > storedCreated) {
        acc[record.taskdetailsid] = record;
      }
    } else if (recordIsActive && !storedIsActive) {
      
      acc[record.taskdetailsid] = record;
    } else if (!recordIsActive && storedIsActive) {
      
    } else if (!recordIsActive && !storedIsActive) {
      
      if (recordActivation < storedActivation) {
        acc[record.taskdetailsid] = record;
      }
    }
  }
  return acc;
}, {});


    const mergedData = taskDetails.map(task => {
      const userTaskProgress = existingData[task.taskdetailsid];
      return {
        taskid: task.taskid,
        taskdetailsid: task.taskdetailsid,
        lastswipedat: userTaskProgress?.completion_date || null,
        phaseid: task.phaseid,
        taskstatus: userTaskProgress?.taskstatus || "Not Started",
        task_activation_date: userTaskProgress?.task_activation_date || null,
        taskdesc: task.taskdesc,
      };
    });

    console.log("[getTaskData] Final merged task data:", mergedData);

    res.status(200).json({ message: "Task data retrieved successfully", data: mergedData });
  } catch (error) {
    console.error("[getTaskData] Error:", error);
    res.status(500).json({ message: "Error retrieving task data", error: error.message });
  }
});


app.post("/api/userprogressStart", verifyToken, async (req, res) => {
  const { phaseId, taskId } = req.body;
  const userId = req.user.id;

  try {
    const { data: taskDetails, error: taskError } = await supabase
      .from("taskdetails")
      .select("*")
      .eq("phaseid", phaseId)
      .eq("taskid", taskId);

    if (taskError || !taskDetails || taskDetails.length === 0) {
      console.log("[userprogressStart] Task details not found.");
      return res.status(404).json({ message: "Task details not found" });
    }

    const taskDetailsId = taskDetails[0].taskdetailsid;


    const { data: existingProgress, error: checkError } = await supabase
      .from("userprogress")
      .select("*")
      .eq("userid", userId)
      .eq("taskdetailsid", taskDetailsId)
      .eq("taskstatus", "In Progress");

    if (existingProgress.length !== 0) {
      console.log("[userprogressStart] Task already in progress.");
      return res.status(409).json({ message: "Progress entry already exists" });
    }


    const taskActivationDate = new Date(Date.now()); // Right now

    const { data, error } = await supabase
      .from("userprogress")
      .insert({
        taskdetailsid: taskDetailsId,
        userid: userId,
        taskstatus: "In Progress",
        created_at: new Date().toISOString(),
        task_activation_date: taskActivationDate.toISOString(),
      })
      .select()
      .single();

    if (error) {
      console.error("[userprogressStart] Error inserting progress:", error);
      throw error;
    }

    console.log("[userprogressStart] Task started successfully:", data);
    res.status(201).json({ message: "User progress started successfully", data });
  } catch (error) {
    console.error("[userprogressStart] Error:", error);
    res.status(500).json({ message: "Error creating userProgress", error: error.message });
  }
});

app.post("/api/userprogressNC", verifyToken, async (req, res) => {
  const userId = req.user.id;
  const { phaseId, taskId, reasonForNonCompletion, failedGoal } = req.body;

  if (!phaseId || !taskId || !reasonForNonCompletion) {
    return res
      .status(400)
      .json({ message: "Required fields missing: phaseId, taskId, reasonForNonCompletion" });
  }

  try {
  
    const { data: currentTask, error: taskError } = await supabase
      .from("taskdetails")
      .select("*")
      .eq("phaseid", phaseId)
      .eq("taskid", taskId)
      .single();

    if (taskError || !currentTask) {
      console.error("[userprogressNC] Task details not found:", taskError);
      return res.status(404).json({ message: "Task details not found" });
    }

    // 2) Mark the existing userprogress entry as "Not Completed"
    const { error: updateError } = await supabase
      .from("userprogress")
      .update({
        taskstatus: "Not Completed",
        completion_date: new Date().toISOString(),
        notcompletionreason: reasonForNonCompletion,
        whichgoal: failedGoal && phaseId === 3 ? failedGoal : null,
      })
      .eq("taskdetailsid", currentTask.taskdetailsid)
      .eq("userid", req.user.id)
      // .eq("taskstatus", "In Progress");

    if (updateError) {
      console.error("[userprogressNC] Error marking current day Not Completed:", updateError);
      return res.status(500).json({ message: "Failed to update userprogress" });
    }


    const nextDay = new Date(Date.now() + 10 * 60 * 60 * 1000);

    const { error: insertError } = await supabase
      .from("userprogress")
      .insert({
        userid: userId,
        taskdetailsid: currentTask.taskdetailsid,
        taskstatus: "Not Started",
        created_at: new Date().toISOString(),
        task_activation_date: nextDay.toISOString(),
      });

    if (insertError) {
      console.error("[userprogressNC] Error inserting same day for tomorrow:", insertError);
      return res.status(500).json({ message: "Failed to insert new userprogress row" });
    }

    return res.status(200).json({
      message: "Task marked Not Completed; same day scheduled for tomorrow.",
    });
  } catch (error) {
    console.error("[userprogressNC] Unexpected error:", error);
    return res.status(500).json({ error: error.message });
  }
});


app.post("/api/userprogressC", verifyToken, async (req, res) => {
  const userId = req.user.id;
  const { phaseId: rawPhase, taskId: rawTask } = req.body;

  try {
    // 1. Convert to numbers (just in case)
    let phaseId = parseInt(rawPhase, 10);
    let taskId = parseInt(rawTask, 10);

    console.log("[userprogressC] Completing (phase=", phaseId, ", task=", taskId, ")");

    // 2. Find the current row in taskdetails
    const { data: currentTask } = await supabase
      .from("taskdetails")
      .select("*")
      .eq("phaseid", phaseId)
      .eq("taskid", taskId)
      .single();

    if (!currentTask) {
      console.error("[userprogressC] Current task not found");
      return res.status(404).json({ message: "Current task not found" });
    }

 
    await supabase
      .from("userprogress")
      .update({
        taskstatus: "Completed",
        completion_date: new Date().toISOString(),
      })
      .eq("taskdetailsid", currentTask.taskdetailsid)
      .eq("userid", userId);


    if (taskId < 5) {
      taskId += 1;
      console.log("[userprogressC] Next day in same phase => (phase=", phaseId, ", day=", taskId, ")");
    } else {
      phaseId += 1;
      taskId = 1;
      console.log("[userprogressC] Jumping to next phase => (phase=", phaseId, ", day=1)");
    }

  
    const { data: nextTask } = await supabase
      .from("taskdetails")
      .select("*")
      .eq("phaseid", phaseId)
      .eq("taskid", taskId)
      .single();

    
    if (!nextTask) {
      console.log("[userprogressC] No row in taskdetails => all tasks done!");
      return res.status(200).json({ message: "All tasks done" });
    }

    const activationDate = new Date(Date.now() +10 * 60 * 60 * 1000); //time lag
    const { error: insertError } = await supabase
      .from("userprogress")
      .insert({
        userid: userId,
        taskdetailsid: nextTask.taskdetailsid,
        taskstatus: "Not Started",
        task_activation_date: activationDate.toISOString(),
        created_at: new Date().toISOString(),
      });

    if (insertError) {
      console.error("[userprogressC] Error inserting next userprogress:", insertError);
      return res.status(500).json({ message: "Failed to insert next userprogress" });
    }

    console.log("[userprogressC] Inserted next day row => (phase=", phaseId, ", task=", taskId, "), activation=now");
    return res
      .status(200)
      .json({ message: "Task completed. Next day set to immediate activation." });
  } catch (error) {
    console.error("[userprogressC] Error:", error);
    return res.status(500).json({ error: error.message });
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
