const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { createClient } = require("@supabase/supabase-js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const pdf = require("html-pdf");
const handlebars = require("handlebars");
const fs = require("fs");
const path = require("path");



dotenv.config();

const app = express();
const PORT = process.env.PORT || 5050;

app.use(express.json());
app.use(cookieParser());

const allowedOrigins = ["https://www.gritfit.site","https://gritfit.vercel.app", "http://localhost:3000"];

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
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.options("*", cors());

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

// getUserNutrition
app.get("/api/getUserNutrition", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id; // or req.user.userid, depending on your JWT
    const { data, error } = await supabase
      .from("user_nutrition")
      .select("*")
      .eq("userid", userId) // CHANGED from .eq("user_id", userId)
      .single();

    if (error) throw error;
    if (!data) {
      return res.status(404).json({ message: "No nutrition data found" });
    }
    return res.status(200).json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/betaSignup", async (req, res) => {
  console.log("Raw Request Body:", req.body);  // Log incoming request body

  const { name, email, message } = req.body;

  console.log("Extracted Fields:", { name, email, message }); 

  try {
      // Insert into the beta_signups table in Supabase
      const { error } = await supabase
          .from("beta_signups")
          .insert([
              {
                  name,
                  email,
                  message,
                  created_at: new Date().toISOString()
              }
          ]);

      if (error) {
          console.error("Error saving beta signup:", error);
          return res.status(500).json({ message: "Failed to save beta signup" });
      }

      return res.status(200).json({ message: "Thanks for signing up! We'll be in touch soon.💪" });
  } catch (err) {
      console.error("Unexpected error saving beta signup:", err);
      res.status(500).json({ message: "Unexpected error", error: err.message });
  }
});


// saveUserNutrition
app.post("/api/saveUserNutrition", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id; // or req.user.userid
    const { age, gender, weight, weightUnit, height, heightUnit, activity, maintenanceCalories } = req.body;

    const { error } = await supabase
      .from("user_nutrition")
      .upsert([
        {
          userid: userId,              // CHANGED from user_id: userId
          age,
          gender,
          weight,
          weight_unit: weightUnit,
          height,
          height_unit: heightUnit,
          activity,
          maintenance_calories: maintenanceCalories,
          updated_at: new Date().toISOString(),
        },
      ]);

    if (error) throw error;
    return res.status(200).json({ message: "User nutrition data saved" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



app.use(express.json());

// 1) Endpoint to generate PDF
app.post("/api/generatePdf", verifyToken, async (req, res) => {
  try {
    // Extract maintenance calories from request
    const { userName, maintenanceCalories } = req.body;

    // 1) Calculate Bulk & Cut Calories
    const targetCaloriesBulk = maintenanceCalories + 500;
    const targetCaloriesCut = maintenanceCalories - 500;
    const targetCaloriesRecomp = maintenanceCalories; // Recomp stays same

    // 2) Calculate Macros (Protein, Fats, Carbs) for Each Goal
    const calculateMacros = (calories) => {
      const proteinCalories = calories * 0.25; // 25% protein
      const carbCalories = calories * 0.50; // 50% carbs
      const fatCalories = calories * 0.25; // 25% fats

      return {
        protein: Math.round(proteinCalories / 4), // 1g protein = 4 kcal
        carbs: Math.round(carbCalories / 4), // 1g carbs = 4 kcal
        fats: Math.round(fatCalories / 9), // 1g fat = 9 kcal
      };
    };

    const macrosBulk = calculateMacros(targetCaloriesBulk);
    const macrosCut = calculateMacros(targetCaloriesCut);
    const macrosRecomp = calculateMacros(targetCaloriesRecomp);

    // 3) Read HTML Template
    const templatePath = path.join(__dirname, "nutritionTemplate.html");
    const htmlContent = fs.readFileSync(templatePath, "utf8");

    // 4) Compile with Handlebars
    const template = handlebars.compile(htmlContent);

    // 5) Generate final HTML with user data
    const finalHtml = template({
      userName,
      maintenanceCalories,
      targetCaloriesBulk,
      targetCaloriesCut,
      targetCaloriesRecomp,
      proteinBulk: macrosBulk.protein,
      proteinCut: macrosCut.protein,
      proteinRecomp: macrosRecomp.protein,
      fatBulk: macrosBulk.fats,
      fatCut: macrosCut.fats,
      fatRecomp: macrosRecomp.fats,
      carbBulk: macrosBulk.carbs,
      carbCut: macrosCut.carbs,
      carbRecomp: macrosRecomp.carbs,
    });

    // 6) Convert HTML to PDF
    const options = { format: "A4" };
    pdf.create(finalHtml, options).toBuffer((err, buffer) => {
      if (err) {
        console.error("Error generating PDF:", err);
        return res.status(500).send("Failed to generate PDF");
      }

      // 7) Send PDF as response
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", 'attachment; filename="Nutrition101.pdf"');
      return res.send(buffer);
    });
  } catch (error) {
    console.error("Error generating PDF:", error);
    res.status(500).send("Failed to generate PDF");
  }
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


app.delete("/api/deleteAccount", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id; // from JWT after verifyToken

    // 1) Delete the user row from userprofile
    //    or set a "deleted" flag if you prefer soft-deletion
    const { error: deleteError } = await supabase
      .from("userprofile")
      .delete()
      .eq("userid", userId);

    if (deleteError) {
      console.error("Error deleting account:", deleteError);
      return res.status(500).json({ message: "Failed to delete account" });
    }

    // 2) Optionally also remove them from other tables, or do so in a single transaction
    // For example, userprogress, user_nutrition, etc.:
    // await supabase.from("userprogress").delete().eq("userid", userId);
    // ... any other cleanup ...

    // 3) Send success response
    return res.status(200).json({ message: "Account deleted successfully" });
  } catch (error) {
    console.error("Delete account error:", error);
    return res.status(500).json({ message: "Server error deleting account" });
  }
});


app.post("/api/restartJourney", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // 1) Delete userprogress rows for this user
    const { error: progressError } = await supabase
      .from("userprogress")
      .delete()
      .eq("userid", userId);

    if (progressError) {
      console.error("Error restarting journey:", progressError);
      return res.status(500).json({ message: "Failed to restart journey" });
    }

    // 2) Optionally reset other tables, like user_nutrition or user_achievements
    //    if you want them truly “fresh”
    // await supabase.from("user_nutrition").delete().eq("userid", userId);
    // or you might just do partial updates, etc.

    // 3) Return success
    return res.status(200).json({ message: "Journey restarted, progress cleared" });
  } catch (error) {
    console.error("Restart journey error:", error);
    return res.status(500).json({ message: "Server error restarting journey" });
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
      .select("username", "email")
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
    return res.status(200).json({
      username: data.username,
      email: data.email,
    });
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
      return res.status(400).json({ message: "Required fields missing: phaseId, taskId, reasonForNonCompletion" });
  }

  try {
      const { data: currentTask, error: taskError } = await supabase
          .from("taskdetails")
          .select("*")
          .eq("phaseid", phaseId)
          .eq("taskid", taskId)
          .single();

      if (taskError || !currentTask) {
          return res.status(404).json({ message: "Task details not found" });
      }

      // Mark current task as "Not Completed"
      const { error: updateError } = await supabase
          .from("userprogress")
          .update({
              taskstatus: "Not Completed",
              completion_date: new Date().toISOString(),
              notcompletionreason: reasonForNonCompletion,
              whichgoal: failedGoal && phaseId === 3 ? failedGoal : null
          })
          .eq("taskdetailsid", currentTask.taskdetailsid)
          .eq("userid", userId);

      if (updateError) {
          console.error("Failed to mark task as Not Completed:", updateError);
          return res.status(500).json({ message: "Failed to update task status." });
      }

      // Check if the cheat day has already been used for this phase
      const { data: cheatCheck, error: cheatCheckError } = await supabase
          .from("user_phase_cheat_tracker")
          .select("cheat_used")
          .eq("userid", userId)
          .eq("phaseid", phaseId)
          .single();

      if (cheatCheckError && cheatCheckError.code !== 'PGRST116') {  // Ignore 'no rows found' error
          console.error("Failed to check phase cheat status:", cheatCheckError);
          return res.status(500).json({ message: "Failed to check cheat day status." });
      }

      const cheatUsed = cheatCheck?.cheat_used || false;
      const nextActivationDate = new Date(Date.now() + 16 * 60 * 60 * 1000); // 10-hour delay

      if ((phaseId === 1 || phaseId === 2) && !cheatUsed) {
          // First time left swipe in this phase — allow cheat, move forward, and mark cheat_used=true

          const { data: nextTask, error: nextTaskError } = await supabase
              .from("taskdetails")
              .select("*")
              .eq("phaseid", phaseId)
              .eq("taskid", taskId + 1)
              .single();

          if (nextTaskError || !nextTask) {
              return res.status(200).json({ message: "No next task available - end of phase." });
          }

          const { error: insertNextTaskError } = await supabase
              .from("userprogress")
              .insert({
                  userid: userId,
                  taskdetailsid: nextTask.taskdetailsid,
                  taskstatus: "Not Started",
                  task_activation_date: nextActivationDate.toISOString(),
                  created_at: new Date().toISOString()
              });

          if (insertNextTaskError) {
              console.error("Failed to insert next task after cheat day:", insertNextTaskError);
              return res.status(500).json({ message: "Failed to insert next task." });
          }

          // Record cheat day usage for this phase
          await supabase
              .from("user_phase_cheat_tracker")
              .upsert([
                  {
                      userid: userId,
                      phaseid: phaseId,
                      cheat_used: true,
                      created_at: new Date().toISOString()
                  }
              ]);

          return res.status(200).json({ message: "Cheat day used - moved to next task." });

      } else if (phaseId === 1 || phaseId === 2) {
          // Cheat already used — repeat same task until completed
          const { error: repeatInsertError } = await supabase
              .from("userprogress")
              .insert({
                  userid: userId,
                  taskdetailsid: currentTask.taskdetailsid,
                  taskstatus: "Not Started",
                  task_activation_date: nextActivationDate.toISOString(),
                  created_at: new Date().toISOString()
              });

          if (repeatInsertError) {
              console.error("Failed to reinsert same task after cheat exhausted:", repeatInsertError);
              return res.status(500).json({ message: "Failed to reschedule task." });
          }

          return res.status(200).json({ message: "Cheat already used - retry same task." });

      } else {
          // Default behavior for Phase 3 and above — always repeat same task
          const { error: normalRetryInsertError } = await supabase
              .from("userprogress")
              .insert({
                  userid: userId,
                  taskdetailsid: currentTask.taskdetailsid,
                  taskstatus: "Not Started",
                  task_activation_date: nextActivationDate.toISOString(),
                  created_at: new Date().toISOString()
              });

          if (normalRetryInsertError) {
              console.error("Failed to reinsert current task:", normalRetryInsertError);
              return res.status(500).json({ message: "Failed to reschedule task." });
          }

          return res.status(200).json({ message: "Task rescheduled for retry." });
      }

  } catch (error) {
      console.error("Unexpected error:", error);
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

    const activationDate = new Date(Date.now() + 16 * 60 * 60 * 1000); //time lag
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
