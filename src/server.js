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
const nodemailer = require("nodemailer");



dotenv.config();

require("./scheduler");

const app = express();
const PORT = process.env.PORT || 5050;

app.use(express.json());
app.use(cookieParser());

const allowedOrigins = ["https://www.gritfit.site","https://gritfit.vercel.app", "http://localhost:3000", "https://gritfit-ui-stage.vercel.app"];

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

// Setup mail transport (Zoho example)
const transporter = nodemailer.createTransport({
  host: "smtp.zoho.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.ZOHO_USER,  // e.g. support@gritfit.site
    pass: process.env.ZOHO_PASS,
  },
  tls: {
    rejectUnauthorized: false,
  },
  requireTLS: false,
  greetingTimeout: 30000, 
});

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
  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "5d" });
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

app.get("/api/admin/analytics", verifyToken, async (req, res) => {
  try {
    const [{ count: totalUsers }, { count: completedTasks }] = await Promise.all([
      supabase.from("userprofile").select("*", { count: "exact", head: true }),
      supabase
        .from("userprogress")
        .select("taskstatus", { count: "exact", head: true })
        .eq("taskstatus", "Completed"),
    ]);

    return res.json({
      totalUsers,
      completedTasks,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("Admin analytics error:", err);
    return res.status(500).json({ error: "Failed to fetch analytics" });
  }
});

app.get("/api/admin/engagementStats", verifyToken, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayISO = today.toISOString();

    // 1️⃣ Fetch progress data
    const { data: progressData = [], error: progressErr } = await supabase
      .from("userprogress")
      .select("userid, taskstatus, completion_date")
      .gte("completion_date", todayISO);
    if (progressErr) throw progressErr;

    // 2️⃣ Extract unique users
    const userIds = [...new Set(progressData.map((item) => item.userid))];

    // 3️⃣ Fetch profiles
    let profiles = [];
    if (userIds.length > 0) {
      const { data: profileData = [], error: profileErr } = await supabase
        .from("userprofile")
        .select("userid, username, email")
        .in("userid", userIds);
      if (profileErr) throw profileErr;
      profiles = profileData;
    }

    // 4️⃣ Map profiles
    const profileMap = {};
    profiles.forEach((p) => {
      profileMap[p.userid] = { name: p.username, email: p.email };
    });

    // 5️⃣ Build DAU user list
    const dauUsers = progressData.map((row) => ({
      userid: row.userid,
      name: profileMap[row.userid]?.name || "Unknown",
      email: profileMap[row.userid]?.email || "Unknown",
      status: row.taskstatus,
      completion_time: row.completion_date,
    }));

    // 6️⃣ Swipe stats
    const swipeCounts = { Completed: 0, "Not Completed": 0, Help: 0 };
    progressData.forEach((item) => {
      if (item.taskstatus === "Completed") swipeCounts.Completed++;
      else if (item.taskstatus === "Not Completed") swipeCounts["Not Completed"]++;
    });

    // 7️⃣ Help stat
    const { data: helpSessions = [], error: helpErr } = await supabase
      .from("help_chat_sessions")
      .select("user_a")
      .gte("created_at", todayISO);
    if (helpErr) throw helpErr;

    swipeCounts.Help = helpSessions.length;

    // ✅ Response
    return res.json({
      dau: userIds.length,
      swipeCounts,
      dauUsers,
    });
  } catch (err) {
    console.error("engagementStats error:", err);
    return res.status(500).json({ error: "Failed to fetch engagement stats" });
  }
});

app.get("/api/admin/forgotPasswordStats", async (req, res) => {
  const projectId = "149785";     // e.g. 123
  const insightId = "KMMhfx25";     // e.g. 456

  try {
    const response = await fetch(`https://app.posthog.com/api/projects/${projectId}/insights/${insightId}/result/`, {
      headers: {
        Authorization: `Bearer ${process.env.POSTHOG_API_KEY}`, // from .env
        "Content-Type": "application/json",
      },
    });

    const json = await response.json();
    return res.json({ insightData: json });
  } catch (err) {
    console.error("PostHog Insight fetch error:", err);
    return res.status(500).json({ error: "Failed to fetch PostHog insight data" });
  }
});



app.get("/api/admin/insights", async (req, res) => {
  const insightMap = {
    forgotPassword: "KMMhfx25",
    bonusCompleted: "U9orR0qO",
  };

  try {
    const fetchInsight = async (id) => {
      const response = await fetch(
        `https://app.posthog.com/api/project/149785/insights/${id}/result/`,
        {
          headers: {
            Authorization: `Bearer ${process.env.POSTHOG_API_KEY}`,
            "Content-Type": "application/json",
          },
        }
      );
      return response.json();
    };

    const results = await Promise.all(
      Object.entries(insightMap).map(async ([key, id]) => {
        const result = await fetchInsight(id);
        return { key, result };
      })
    );

    const combined = {};
    results.forEach(({ key, result }) => {
      combined[key] = result;
    });

    res.json(combined);
  } catch (err) {
    console.error("PostHog insights fetch error:", err);
    res.status(500).json({ error: "Failed to fetch insight data" });
  }
});

// 🔄 Replaced static insight fetch with dynamic Query API for real-time counts
app.post("/api/admin/posthog/events", async (req, res) => {
  const apiKey = process.env.POSTHOG_API_KEY;
  const { eventNames = [], days = 7 } = req.body;

  if (!Array.isArray(eventNames) || eventNames.length === 0) {
    return res.status(400).json({ error: "eventNames array is required" });
  }

  try {
    // Helper to fetch the count for one event
    const fetchCount = async (event) => {
      const response = await fetch(
        `https://us.posthog.com/api/project/149785/query/`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            kind: "TrendsQuery",
            query: {
              series: [{ event, kind: "EventsQuery" }],
              dateRange: { date_from: `-${days}d` },
            },
          }),
        }
      );

      if (!response.ok) {
        const errTxt = await response.text();
        throw new Error(`PostHog query failed for '${event}': ${errTxt}`);
      }

      const json = await response.json();
      // Sum up the series data array
      const count = Array.isArray(json[0]?.data)
        ? json[0].data.reduce((sum, v) => sum + (v || 0), 0)
        : 0;
      return { event, count };
    };

    // Parallel fetch all events
    const results = await Promise.all(eventNames.map(fetchCount));

    // Convert to object map
    const eventCounts = {};
    results.forEach(({ event, count }) => {
      eventCounts[event] = count;
    });

    res.json(eventCounts);
  } catch (error) {
    console.error("PostHog dynamic events error:", error);
    res.status(500).json({ error: "Failed to fetch PostHog event data" });
  }
});


app.get("/api/admin/userProgressMetrics", verifyToken, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayISO = today.toISOString();


    const { data: progressRows } = await supabase
      .from("userprogress")
      .select("userid")
      .gte("created_at", todayISO);
    const dau = new Set(progressRows.map((r) => r.userid)).size;


    const { count: completedTasks } = await supabase
      .from("userprogress")
      .select("*", { head: true, count: "exact" })
      .eq("taskstatus", "Completed");

 
    const { count: notCompletedTasks } = await supabase
      .from("userprogress")
      .select("*", { head: true, count: "exact" })
      .eq("taskstatus", "Not Completed");

    const { count: helpRequests } = await supabase
      .from("help_chat_sessions")
      .select("*", { head: true, count: "exact" })
      .gte("created_at", todayISO);


    const { count: helpMessages } = await supabase
      .from("help_chat_messages")
      .select("*", { head: true, count: "exact" })
      .gte("created_at", todayISO);


    const avgMessagesPerSession =
      helpRequests > 0 ? (helpMessages / helpRequests).toFixed(2) : 0;

    // 8. Drop‑off Points: how many distinct tasks ended “Not Completed”
    const { data: dropped } = await supabase
      .from("userprogress")
      .select("taskdetailsid", { distinct: true })
      .eq("taskstatus", "Not Completed");
    const dropOffPoints = dropped.length;

    // Return all metrics
    res.json({
      dau,
      completedTasks,
      notCompletedTasks,
      helpRequests,
      helpMessages,
      avgMessagesPerSession,
      dropOffPoints,
    });
  } catch (err) {
    console.error("userProgressMetrics error:", err);
    res.status(500).json({ error: "Failed to fetch user progress metrics" });
  }
});

app.get("/api/admin/engagementStats", verifyToken, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayISO = today.toISOString();


    const { data: helpSessions = [], error: helpErr } = await supabase
      .from("help_chat_sessions")
      .select("user_a, created_at")
      .gte("created_at", todayISO);
    if (helpErr) throw helpErr;

    // 3) Grab the unique user_a IDs
    const helpUserIds = [...new Set(helpSessions.map((s) => s.user_a))];

    // 4) Fetch their profiles
    let helpProfiles = [];
    if (helpUserIds.length) {
      const { data: hp, error: hpErr } = await supabase
        .from("userprofile")
        .select("userid, username, email")
        .in("userid", helpUserIds);
      if (hpErr) throw hpErr;
      helpProfiles = hp;
    }

    // 5) Build a quick lookup map
    const profileMap = {};
    helpProfiles.forEach((p) => {
      profileMap[p.userid] = { name: p.username, email: p.email };
    });

    // 6) Map into a helpUsers array with full details
    const helpUsers = helpSessions.map((s) => ({
      userid: s.user_a,
      name: profileMap[s.user_a]?.name || "Unknown",
      email: profileMap[s.user_a]?.email || "Unknown",
      requested_at: s.created_at,
    }));

    // 7) Now return everything (plus your existing dau, swipeCounts, dauUsers…)
    return res.json({
      dau,
      swipeCounts,
      dauUsers,
      helpUsers,
    });
  } catch (err) {
    console.error("engagementStats error:", err);
    return res.status(500).json({ error: "Failed to fetch engagement stats" });
  }
});

app.get("/api/admin/users", verifyToken, async (req, res) => {
  try {
    const { data, error } = await supabase   // 👈 select the right column names
      .from("userprofile")
      .select("userid, username, email")
      .order("created_at", { ascending: false });

    if (error) throw error;
    return res.json(data);              // ⇒ [{ userid: "...", username:"Dhruv", email:"..."}, …]
  } catch (err) {
    console.error("users list error:", err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

// GET all the core analytics in one shot
app.get("/api/admin/fullAnalytics", verifyToken, async (req, res) => {
  try {
    // midnight today
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayISO = today.toISOString();

    // 1) DAUs (distinct users who did >1 progress update today)
    const { count: dau } = await supabase
      .from("userprogress")
      .select("userid", { count: "exact", head: true })
      .gte("created_at", todayISO);

    // 2) Completed / Not Completed Tasks (all-time)
    const [{ count: completedTasks }, { count: notCompletedTasks }] = await Promise.all([
      supabase
        .from("userprogress")
        .select("*", { count: "exact", head: true })
        .eq("taskstatus", "Completed"),
      supabase
        .from("userprogress")
        .select("*", { count: "exact", head: true })
        .eq("taskstatus", "Not Completed"),
    ]);

    // 3) Drop-Off Points (today’s flips from In Progress → Not Completed)
    //    Simplest: count “Not Completed” entries created today
    const { count: dropOffPoints } = await supabase
      .from("userprogress")
      .select("*", { count: "exact", head: true })
      .eq("taskstatus", "Not Completed")
      .gte("completion_date", todayISO);

    // 4) Community / Help stats
    const [
      { count: helpRequestsToday },
      { count: helpMessagesToday },
      { count: helpRewardsToday },
    ] = await Promise.all([
      supabase
        .from("help_chat_sessions")
        .select("*", { count: "exact", head: true })
        .gte("created_at", todayISO),
      supabase
        .from("help_chat_messages")
        .select("*", { count: "exact", head: true })
        .gte("created_at", todayISO),
      supabase
        .from("help_chat_messages")
        .select("*", { count: "exact", head: true })
        .gte("created_at", todayISO)
        .eq("is_helpful", true),
    ]);

    // 5) Forgot-password rate (approx via reset_code usage in userprofile)
    const { count: forgotPasswordCount } = await supabase
      .from("userprofile")
      .select("*", { count: "exact", head: true })
      .not("reset_code", "is", null);

    return res.json({
      dau,
      completedTasks,
      notCompletedTasks,
      dropOffPoints,
      helpRequestsToday,
      helpMessagesToday,
      helpRewardsToday,
      forgotPasswordCount,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("fullAnalytics error:", err);
    res.status(500).json({ error: "Failed to fetch full analytics" });
  }
});

// ─── GET /api/admin/userSummary/:userid ────────────────────────────────
app.get("/api/admin/userSummary/:userid", verifyToken, async (req, res) => {
  const userId = req.params.userid;
  if (!userId) return res.status(400).json({ error: "Missing user ID" });

  try {
    /* ------------------------------------------------------------------ */
    /*  0)  CONSTANTS + HELPERS                                           */
    /* ------------------------------------------------------------------ */
    const today      = new Date(); today.setHours(0, 0, 0, 0);
    const todayISO   = today.toISOString();
    const safeArr    = (x) => (Array.isArray(x) ? x : []);

    /* ------------------------------------------------------------------ */
    /*  1)  PROFILE (gems, timezone, created_at)                          */
    /* ------------------------------------------------------------------ */
    const { data: userProfile, error: profErr } = await supabase
      .from("userprofile")
      .select("username,email,timezone,gems,created_at")
      .eq("userid", userId)
      .single();
    if (profErr) throw profErr;

    const userTZ = userProfile.timezone || "UTC";

    /* ------------------------------------------------------------------ */
    /*  2)  PROGRESS ROWS                                                 */
    /* ------------------------------------------------------------------ */
    const { data: rawProgress, error: progErr } = await supabase
      .from("userprogress")
      .select("taskstatus,completion_date,taskdetailsid,created_at")
      .eq("userid", userId);
    if (progErr) throw progErr;
    const progress = safeArr(rawProgress);

    const tasksCompleted     = progress.filter(p => p.taskstatus === "Completed").length;
    const tasksNotCompleted  = progress.filter(p => p.taskstatus === "Not Completed").length;
    const dropOffs           = progress
      .filter(p => p.taskstatus === "Not Completed")
      .map(p   => p.taskdetailsid);

    /* ------------------------------------------------------------------ */
    /*  3)  TODAY’S ACTIVITY FOR DAU FLAG                                 */
    /* ------------------------------------------------------------------ */
    const [{ count: progressToday }] = await Promise.all([
      supabase
        .from("userprogress")
        .select("*", { head: true, count: "exact" })
        .eq("userid", userId)
        .gte("created_at", todayISO)
    ]);

    /* ------------------------------------------------------------------ */
    /*  4)  HELP SESSIONS & MESSAGES                                      */
    /* ------------------------------------------------------------------ */
    const [
      { data: rawHelpInitiated, error: hInitErr },
      { data: rawHelpReceived,  error: hRecvErr },
      { count: helpfulMessagesSent }
    ] = await Promise.all([
      supabase
        .from("help_chat_sessions")
        .select("id,created_at")
        .eq("user_a", userId),
      supabase
        .from("help_chat_sessions")
        .select("id,created_at")
        .eq("user_b", userId),
      supabase
        .from("help_chat_messages")
        .select("*", { head: true, count: "exact" })
        .eq("sender_id", userId)
        .eq("is_helpful", true)
    ]);
    if (hInitErr) throw hInitErr;
    if (hRecvErr) throw hRecvErr;

    const helpInitiated = safeArr(rawHelpInitiated);
    const helpReceived  = safeArr(rawHelpReceived);

    const helpToday =
      helpInitiated.filter(h => h.created_at >= todayISO).length +
      helpReceived .filter(h => h.created_at >= todayISO).length;

    /* ------------------------------------------------------------------ */
    /*  5)  STREAK CALC (current / longest / breaks)                      */
    /* ------------------------------------------------------------------ */
    const completedDays = [...new Set(
      progress
        .filter(p => p.taskstatus === "Completed" && p.completion_date)
        .map(p => new Date(p.completion_date)
          .toLocaleDateString("en-CA", { timeZone: userTZ })) // YYYY-MM-DD
    )].sort();  // ascending

    let currentStreak = 0, longestStreak = 0, streakBreaks = 0;
    if (completedDays.length) {
      let prev = null;
      completedDays.forEach(day => {
        if (!prev) {                       // first day
          currentStreak = 1;
        } else {
          const gap = (new Date(day) - new Date(prev)) / 86_400_000;
          if (gap === 1) {                 // consecutive
            currentStreak++;
          } else if (gap > 1) {            // break
            longestStreak = Math.max(longestStreak, currentStreak);
            streakBreaks++;
            currentStreak = 1;
          }
        }
        prev = day;
      });
      longestStreak = Math.max(longestStreak, currentStreak);

      const todayStr = new Date().toLocaleDateString("en-CA", { timeZone: userTZ });
      if (!completedDays.includes(todayStr)) currentStreak = 0;
    }

    /* ------------------------------------------------------------------ */
    /*  6)  MOST RECENT TASK                                              */
    /* ------------------------------------------------------------------ */
    const { data: lastRow } = await supabase
      .from("userprogress")
      .select("taskdetailsid")
      .eq("userid", userId)
      .order("created_at", { ascending: false })
      .limit(1)
      .single();
    const currentTask = lastRow?.taskdetailsid || null;


        // ------------------------------------------------------------------
    // 7)   FRIENDS  – how many *accepted* rows reference this user
    // ------------------------------------------------------------------
    const { count: friendsAdded } = await supabase
      .from("friend_requests")
      .select("*", { count: "exact", head: true })
      .or(`from_user.eq.${userId},to_user.eq.${userId}`)
      .eq("status", "accepted");

    /* ------------------------------------------------------------------ */
    /*  8)  RESPONSE                                                      */
    /* ------------------------------------------------------------------ */
    return res.json({
      userProfile,
      accountCreated   : userProfile.created_at,

      isActiveToday    : (progressToday + helpToday) > 0,

      currentStreak,
      longestStreak,
      streakBreaks,
      currentTask,

      stats: {
        tasksCompleted,
        tasksNotCompleted,
        helpSent            : helpInitiated.length,
        helpReceived        : helpReceived.length,
        helpfulContributions: helpfulMessagesSent,
        friendsAdded          : friendsAdded  
      },

      dropOffs,
      gems: userProfile.gems || 0
    });

  } catch (err) {
    console.error("userSummary error:", err);
    res.status(500).json({ error: "Failed to fetch user summary", details: err.message });
  }
});


app.get("/api/admin/nutritionStats", verifyToken, async (req, res) => {
  try {
    
    const midnight = new Date();
    midnight.setHours(0, 0, 0, 0);
    const todayISO = midnight.toISOString();

    /* ---------------------------------------------------------------
       1) “First-time” submissions today
       --------------------------------------------------------------- */
    const { count: firstTime } = await supabase
      .from("user_nutrition")
      .select("*", { head: true, count: "exact" })
      .gte("created_at", todayISO)
      .lte("updated_at", supabase.rpc("add_seconds", { ts: "created_at", s: 1 }));

    /* ---------------------------------------------------------------
       2) Edits today (updated_at ≥ today && updated_at > created_at)
       --------------------------------------------------------------- */
    const { count: updates } = await supabase
      .from("user_nutrition")
      .select("*", { head: true, count: "exact" })
      .gte("updated_at", todayISO)
      .gt("updated_at", "created_at");

    /* ---------------------------------------------------------------
       3) Distinct users who touched it today
       --------------------------------------------------------------- */
    const { count: activeUsersToday } = await supabase
      .from("user_nutrition")
      .select("userid", { head: true, count: "exact" })
      .gte("updated_at", todayISO);

    /* ---------------------------------------------------------------
       4) Lifetime rows & distinct users  (to get avg uses / user)
       --------------------------------------------------------------- */
    const [
      { count: totalRows },
      { count: distinctUsers }
    ] = await Promise.all([
      supabase                           
        .from("user_nutrition")
        .select("*", { head: true, count: "exact" }),
      supabase                           // distinct non-null users
        .from("user_nutrition")
        .select("userid", { head: true, count: "exact" })
        .not("userid", "is", null)
    ]);

    const avgUsesPerUser =
      distinctUsers ? (totalRows / distinctUsers).toFixed(2) : "0";

    
    return res.json({
      firstTime,
      updates,
      activeUsersToday,
      avgUsesPerUser,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("nutritionStats error:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch nutrition stats", details: err.message });
  }
});


// notifications
app.post("/api/storeBeamsDevice", verifyToken, async (req, res) => {
  try {
    const { deviceId } = req.body;
    const userId = req.user.id; // from verifyToken (JWT decode)

    // deviceId === null => unsubscribing
    // deviceId is string => subscribing
    const { data, error } = await supabase
      .from("userprofile")
      .update({ beams_device_id: deviceId })
      .eq("userid", userId);

    if (error) {
      console.error("Error storing Beams device ID:", error);
      return res.status(500).json({ message: "Failed to update device ID" });
    }
    return res.status(200).json({ message: "Beams device ID updated successfully" });
  } catch (err) {
    console.error("Error in /api/storeBeamsDevice:", err);
    res.status(500).json({ message: "Server error" });
  }
});


app.get("/api/searchUsers", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id; // from your JWT decode
    const query = req.query.query || "";

    if (!query.trim()) {
      return res.status(200).json({ results: [] });
    }

    // 1) Search for potential matches in userprofile
    const { data: allMatches, error } = await supabase
    .from("userprofile")
    .select("userid, username, email")
    .or(
      `username.ilike.%${query}%,email.ilike.%${query}%`
    );
  

    if (error) throw error;

    // 2) Alternatively, if you also want to match email in a single query:
    //    With Supabase you can do:
    /*
    .or(
      `username.ilike.%${query}%,email.ilike.%${query}%`
    );
    */

    // Filter out yourself
    const filtered = (allMatches || []).filter((u) => u.userid !== userId);

    // 3) Optionally also filter out already-friends if you want
    /*
      const { data: existingFriends } = await supabase
        .from("user_friends")
        .select("friend_id")
        .eq("user_id", userId);

      const friendIds = existingFriends.map(f => f.friend_id);
      const finalResults = filtered.filter(u => !friendIds.includes(u.userid));
    */

    return res.status(200).json({ results: filtered });
  } catch (err) {
    console.error("searchUsers error:", err);
    return res.status(500).json({ error: err.message });
  }
});


app.post("/api/addFriend", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id; // the current user from JWT
    const { friendId } = req.body;

    if (!friendId) {
      return res.status(400).json({ error: "Missing friendId." });
    }

    // 1. Prevent adding yourself
    if (userId === friendId) {
      return res.status(400).json({ error: "Cannot add yourself as friend." });
    }

    // 2. Check if user already has 3 friends
    const { data: existingFriends, error: friendError } = await supabase
      .from("user_friends")
      .select("friend_id")
      .eq("user_id", userId);

    if (friendError) throw friendError;

    if (existingFriends && existingFriends.length >= 3) {
      return res
        .status(400)
        .json({ error: "Friend limit reached (3). Cannot add more friends." });
    }

    // 3. Check if friendId is valid user in userprofile
    const { data: foundUser, error: userError } = await supabase
      .from("userprofile")
      .select("*")
      .eq("userid", friendId)
      .single();

    if (userError) throw userError;
    if (!foundUser) {
      return res.status(404).json({ error: "That user does not exist." });
    }

    // 4. Check if already a friend
    const isAlreadyFriend = existingFriends.some((f) => f.friend_id === friendId);
    if (isAlreadyFriend) {
      return res.status(400).json({ error: "You are already friends with this user." });
    }

    // 5. Insert new row
    const { error: insertError } = await supabase
      .from("user_friends")
      .insert([{ user_id: userId, friend_id: friendId }]);

    if (insertError) throw insertError;

    return res.status(200).json({ message: "Friend added successfully." });
  } catch (err) {
    console.error("addFriend error:", err);
    return res.status(500).json({ error: err.message });
  }
});


app.get("/api/friends", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // 1) Find all friend_ids for user
    const { data: friendRows, error: friendErr } = await supabase
      .from("user_friends")
      .select("friend_id")
      .eq("user_id", userId);

    if (friendErr) throw friendErr;
    if (!friendRows || friendRows.length === 0) {
      return res.json({ friends: [] });
    }

    // 2) Gather friendIds
    const friendIds = friendRows.map((r) => r.friend_id);

    // 3) Fetch userprofile for each friend
    const { data: profiles, error: profileErr } = await supabase
      .from("userprofile")
      .select("userid, username, email")
      .in("userid", friendIds);

    if (profileErr) throw profileErr;

    // 4) Format as needed by your frontend
    const result = profiles.map((p) => ({
      id: p.userid,
      name: p.username,
      email: p.email,
    }));
    return res.json({ friends: result });
  } catch (err) {
    console.error("GET /api/friends error:", err);
    res.status(500).json({ error: err.message });
  }
});


app.get("/api/getFriendRequests", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    // With Supabase, if you've declared a foreign key:
    // friend_requests.from_user -> userprofile.userid
    // friend_requests.to_user   -> userprofile.userid
    // Then you can do something like:
    const { data: requests, error } = await supabase
      .from("friend_requests")
      .select(`
        id,
        status,
        created_at,
        from_user (userid, username, email),
        to_user
      `)
      .eq("to_user", userId)
      .eq("status", "pending");

    if (error) throw error;

    // "from_user" will be an object like { userid, username, email }
    return res.json({ requests });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.delete("/api/removeFriend/:friendId", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { friendId } = req.params;

    // 1) Delete both directions: (userId->friendId) and (friendId->userId)
    const { error } = await supabase
      .from("user_friends")
      .delete()
      .or(
        `and(user_id.eq.${userId},friend_id.eq.${friendId}),and(user_id.eq.${friendId},friend_id.eq.${userId})`
      );

    if (error) throw error;

    return res.json({ message: "Friend removed successfully." });
  } catch (err) {
    console.error("DELETE /api/removeFriend/:friendId error:", err);
    res.status(500).json({ error: err.message });
  }
});


app.post("/api/sendFriendRequest", verifyToken, async (req, res) => {
  try {
    const fromUser = req.user.id;
    const { toUserId } = req.body;

    if (!toUserId) {
      return res.status(400).json({ error: "Missing toUserId." });
    }
    if (fromUser === toUserId) {
      return res.status(400).json({ error: "Cannot send request to yourself." });
    }

    // Check if request already exists or if user already a friend, etc.
    // For brevity, we won't do that here. Just insert a new request.

    const { error: insertErr } = await supabase
      .from("friend_requests")
      .insert([
        { from_user: fromUser, to_user: toUserId, status: "pending" },
      ]);

    if (insertErr) throw insertErr;

    return res.json({ message: "Friend request sent." });
  } catch (err) {
    console.error("POST /api/sendFriendRequest error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/respondFriendRequest", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id; // the "to_user"
    const { requestId, accept } = req.body;

    // 1) Find that request
    const { data: reqRow, error: findErr } = await supabase
      .from("friend_requests")
      .select("*")
      .eq("id", requestId)
      .single();

    if (findErr) throw findErr;
    if (!reqRow) {
      return res.status(404).json({ error: "Friend request not found." });
    }
    if (reqRow.to_user !== userId) {
      return res.status(403).json({ error: "Not authorized to respond." });
    }
    if (reqRow.status !== "pending") {
      return res.status(400).json({ error: "Request is not pending." });
    }

    if (accept) {
      // 2a) Accept => set request to 'accepted'
      const { error: updateErr } = await supabase
        .from("friend_requests")
        .update({ status: "accepted" })
        .eq("id", requestId);

      if (updateErr) throw updateErr;

      // 2b) Insert symmetrical rows in user_friends (both ways)
      // You can also check each user’s friend limit first, if desired.
      const { error: insertFriendsErr } = await supabase
        .from("user_friends")
        .insert([
          { user_id: reqRow.from_user, friend_id: reqRow.to_user },
          { user_id: reqRow.to_user, friend_id: reqRow.from_user },
        ]);

      if (insertFriendsErr) throw insertFriendsErr;

      return res.json({ message: "Friend request accepted." });
    } else {
      // 3) Reject => set request to 'rejected'
      const { error: rejectErr } = await supabase
        .from("friend_requests")
        .update({ status: "rejected" })
        .eq("id", requestId);

      if (rejectErr) throw rejectErr;

      return res.json({ message: "Friend request rejected." });
    }
  } catch (err) {
    console.error("respondFriendRequest error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/createHelpSessions", verifyToken, async (req, res) => {
  try {
    const userA = req.user.id;  // the help seeker
    const { taskdetailsid, friendIds } = req.body;

    if (!taskdetailid || !friendIds?.length) {
      return res.status(400).json({ error: "Missing taskdetailid or friendIds." });
    }

    // Build rows for each friend
    const sessionsToInsert = friendIds.map((friendId) => ({
      user_a: userA,
      user_b: friendId,
      taskdetailsid: taskdetailsid
    }));

    const { data, error } = await supabase
      .from("help_chat_sessions")
      .insert(sessionsToInsert)
      .select(); // get created rows back

    if (error) throw error;

    // Return the newly created session rows, each with an 'id'
    return res.json({ sessions: data });
  } catch (err) {
    console.error("createHelpSessions error:", err);
    return res.status(500).json({ error: err.message });
  }
});

/*
  2) POST /api/sendHelpMessage
     Add a new message to a session, enforcing the 4-message limit.
     Body: { sessionId, content }
*/
app.post("/api/sendHelpMessage", verifyToken, async (req, res) => {
  try {
    const senderId = req.user.id;
    const { sessionId, content } = req.body;

    if (!sessionId || !content?.trim()) {
      return res.status(400).json({ error: "Missing sessionId or content." });
    }

    // 1) Check if session actually belongs to this user or user is the friend
    const { data: sessionData, error: sessionErr } = await supabase
      .from("help_chat_sessions")
      .select("*")
      .eq("id", sessionId)
      .single();

    if (sessionErr || !sessionData) {
      return res.status(404).json({ error: "Session not found." });
    }
    // user must be user_a or user_b
    if (![sessionData.user_a, sessionData.user_b].includes(senderId)) {
      return res.status(403).json({ error: "Not authorized for this session." });
    }

    // 2) Count how many messages exist
    const { data: existingMsgs, error: msgErr } = await supabase
      .from("help_chat_messages")
      .select("id")
      .eq("session_id", sessionId);

    if (msgErr) throw msgErr;
    if (existingMsgs.length >= 4) {
      return res.status(400).json({ error: "Max 4 messages reached." });
    }

    // 3) Insert new message
    const { data: newMsg, error: insertErr } = await supabase
      .from("help_chat_messages")
      .insert([
        { 
          session_id: sessionId, 
          sender_id: senderId, 
          content: content.trim() // or encrypted content
        }
      ])
      .select()
      .single();

    if (insertErr) throw insertErr;

    return res.json({ message: newMsg });
  } catch (err) {
    console.error("sendHelpMessage error:", err);
    return res.status(500).json({ error: err.message });
  }
});


app.post("/api/sendHelpRequest", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id; // the help-seeker
    const { phaseNumber, dayNumber, message } = req.body;

    // 1) Validate input
    if (!phaseNumber || !dayNumber || !message?.trim()) {
      return res.status(400).json({ error: "Missing phaseNumber, dayNumber, or message." });
    }

    // 2) Find user’s friends
    const { data: friendRows, error: friendErr } = await supabase
      .from("user_friends")
      .select("friend_id")
      .eq("user_id", userId);
    if (friendErr) throw friendErr;

    if (!friendRows || friendRows.length === 0) {
      return res.status(400).json({ error: "You have no friends to send help request to." });
    }

    // 3) Get taskdetailid from (phaseNumber, dayNumber)
    const { data: taskDetails, error: taskErr } = await supabase
      .from("taskdetails") 
      .select("taskdetailsid, taskdesc")
      .eq("phaseid", phaseNumber)
      .eq("taskid", dayNumber)
      .single();

    if (taskErr || !taskDetails) {
      return res.status(404).json({ error: "Task detail not found for the given phase/day." });
    }
    const { taskdetailsid, taskdesc } = taskDetails;

    // 4) [New] Check if user has already created a help request for this task
    //    i.e. any session with (user_a = current user) AND (taskdetailid = found ID)
    const { data: existingSessions, error: checkErr } = await supabase
      .from("help_chat_sessions")
      .select("id")
      .match({ user_a: userId, taskdetailsid });

    if (checkErr) throw checkErr;

    if (existingSessions.length > 0) {
      // This means user has already created a help chat for that task
      return res.status(400).json({
        error: "You have already requested help for this task.",
      });
    }

    // 5) Create new help_chat_sessions for each friend
    const sessionsToInsert = friendRows.map((f) => ({
      user_a: userId,
      user_b: f.friend_id,
      taskdetailsid: taskdetailsid,
    }));

    const { data: insertedSessions, error: insertErr } = await supabase
      .from("help_chat_sessions")
      .insert(sessionsToInsert)
      .select();
    if (insertErr) throw insertErr;

    // 6) Insert the initial message
    // Optionally embed the taskdesc in the first message for context
    const combinedMessage = message.trim();

    const messagesToInsert = insertedSessions.map((sess) => ({
      session_id: sess.id,
      sender_id: userId,
      content: combinedMessage,
    }));

    const { error: msgErr } = await supabase
      .from("help_chat_messages")
      .insert(messagesToInsert);
    if (msgErr) throw msgErr;

    return res.json({
      message: "Help request sent to all friends!",
      sessionsCreated: insertedSessions.length,
      sessions: insertedSessions,
    });
  } catch (err) {
    console.error("sendHelpRequest error:", err);
    return res.status(500).json({ error: err.message });
  }
});


app.get("/api/helpMessages/:sessionId", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { sessionId } = req.params;

    // Check session
    const { data: sessionData, error: sessionErr } = await supabase
      .from("help_chat_sessions")
      .select("*")
      .eq("id", sessionId)
      .single();

    if (sessionErr || !sessionData) {
      return res.status(404).json({ error: "Session not found." });
    }
    if (![sessionData.user_a, sessionData.user_b].includes(userId)) {
      return res.status(403).json({ error: "Not authorized for this session." });
    }

    // Fetch messages
    const { data: msgs, error: msgsErr } = await supabase
      .from("help_chat_messages")
      .select("id, sender_id, content, created_at, sender:userprofile(username)")
      .eq("session_id", sessionId)
      .order("created_at", { ascending: true });

    if (msgsErr) throw msgsErr;

    const transformed = msgs.map((m) => ({
      ...m,
      // Convert from UTC to Asia/Kolkata, for example:
      formatted_time: moment.utc(m.created_at).tz("Asia/Kolkata").format("YYYY-MM-DD HH:mm"),
    }));

    return res.json({ messages: transformed });
  } catch (err) {
    console.error("GET /helpMessages error:", err);
    return res.status(500).json({ error: err.message });
  }
});


app.get("/api/myHelpSessions", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const { data: sessions, error } = await supabase
      .from("help_chat_sessions")
      .select(`
        id,
        user_a,
        user_b,
        taskdetails (
          taskdesc
        ),
        user_a_profile: userprofile!help_chat_sessions_user_a_fkey ( userid, username ),
        user_b_profile: userprofile!help_chat_sessions_user_b_fkey ( userid, username )
      `)
      // Return all sessions where I'm user_a or user_b
      .or(`user_a.eq.${userId},user_b.eq.${userId}`);

    if (error) throw error;
    return res.json({ sessions });
  } catch (err) {
    console.error("myHelpSessions error:", err);
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/markMessageHelpful", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { messageId, rating } = req.body;

    // rating should be one of: "helpful", "somewhat", or "not".
    if (!messageId || !rating) {
      return res.status(400).json({ error: "Missing messageId or rating." });
    }
    if (!["helpful", "somewhat", "not"].includes(rating)) {
      return res.status(400).json({ error: "Invalid rating option." });
    }

    // A small map from rating -> gems.
    const ratingToGems = {
      helpful: 10,
      somewhat: 5,
      not: 0,
    };

    // 1) Fetch the message
    const { data: messageData, error: msgErr } = await supabase
      .from("help_chat_messages")
      .select("*")
      .eq("id", messageId)
      .single();
    if (msgErr || !messageData) {
      return res.status(404).json({ error: "Message not found." });
    }

    // 2) Retrieve the chat session and verify user is a participant
    const { data: sessionData, error: sessErr } = await supabase
      .from("help_chat_sessions")
      .select("*")
      .eq("id", messageData.session_id)
      .single();
    if (sessErr || !sessionData) {
      return res.status(404).json({ error: "Session not found." });
    }
    if (![sessionData.user_a, sessionData.user_b].includes(userId)) {
      return res.status(403).json({ error: "Not authorized to rate this message." });
    }

    // 3) Prevent rating your own message
    if (messageData.sender_id === userId) {
      return res
        .status(400)
        .json({ error: "You cannot rate your own message." });
    }

    // 4) Check if any message in the session already has a rating
    const { data: existingRatings, error: helpfulErr } = await supabase
      .from("help_chat_messages")
      .select("id")
      .eq("session_id", messageData.session_id)
      .in("rating", ["helpful", "somewhat", "not"]); // any rating
    if (helpfulErr) {
      return res
        .status(500)
        .json({ error: "Error checking for existing ratings in this session." });
    }
    if (existingRatings && existingRatings.length > 0) {
      // Means a message has already been rated
      return res
        .status(400)
        .json({ error: "A message in this chat has already been rated." });
    }

    // 5) Ensure this message is not the first message of the session (the "help request")
    const { data: firstMessage, error: firstMsgErr } = await supabase
      .from("help_chat_messages")
      .select("id, created_at")
      .eq("session_id", messageData.session_id)
      .order("created_at", { ascending: true })
      .limit(1)
      .single();
    if (firstMsgErr || !firstMessage) {
      return res.status(500).json({ error: "Error retrieving the first message." });
    }
    if (firstMessage.id === messageData.id) {
      return res
        .status(400)
        .json({ error: "You cannot rate the initial help request." });
    }

    // 6) Update the message with the given rating
    const { error: updateMsgErr } = await supabase
      .from("help_chat_messages")
      .update({
        rating,
        helpful_by: userId,
      })
      .eq("id", messageId);
    if (updateMsgErr) throw updateMsgErr;

    // 7) Award gems depending on the rating
    const gemAward = ratingToGems[rating];
    if (gemAward > 0) {
      const friendId = messageData.sender_id;
      const { data: friendProfile, error: friendErr } = await supabase
        .from("userprofile")
        .select("gems")
        .eq("userid", friendId)
        .single();
      if (friendErr || !friendProfile) {
        return res.status(404).json({ error: "Sender's profile not found." });
      }
      const newGems = (friendProfile.gems || 0) + gemAward;
      const { error: updateGemErr } = await supabase
        .from("userprofile")
        .update({ gems: newGems })
        .eq("userid", friendId);
      if (updateGemErr) throw updateGemErr;
    }

    return res.json({
      message: `Message rated as "${rating}". Awarded ${gemAward} gems to the sender.`,
    });
  } catch (err) {
    console.error("Error in markMessageHelpful:", err);
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/updateAvatarColor", verifyToken, async (req, res) => {
  try {
    const { newAvatarColor } = req.body;
    const email = req.user.email;

    const { data, error } = await supabase
      .from("userprofile")
      .update({ avatar_color: newAvatarColor })
      .eq("email", email);

    if (error) throw error;

    return res.status(200).json({ message: "Avatar color updated successfully", data });
  } catch (err) {
    console.error("Error updating avatar color:", err);
    res.status(500).json({ message: "Error updating avatar color", error: err.message });
  }
});

app.get("/api/getUserGems", verifyToken, async (req, res) => {
  try {

    const userId = req.user.id;  
    const { data, error } = await supabase
      .from("userprofile")
      .select("gems")
      .eq("userid", userId)
      .single();

    if (error) {
      console.error("Error fetching user gems:", error);
      return res.status(500).json({ error: "Internal server error" });
    }

    if (!data) {
      return res.status(404).json({ error: "User profile not found" });
    }

    return res.json({ gems: data.gems });
  } catch (err) {
    console.error("Unexpected error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/updateUserGems", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id; // or use email if that’s your key
    const { newGemCount } = req.body;
    if (typeof newGemCount !== "number") {
      return res.status(400).json({ error: "Invalid gem count" });
    }

    const { error } = await supabase
      .from("userprofile")
      .update({ gems: newGemCount })
      .eq("userid", userId); // Adjust field name according to your schema

    if (error) throw error;

    return res.json({ success: true, gems: newGemCount });
  } catch (err) {
    console.error("updateUserGems error:", err);
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/unlockBonus", verifyToken, async (req, res) => {
  const userId = req.user.id;
  const { phaseId } = req.body;  // phaseId sent from frontend

  try {
    // Get the current phase from the user profile if not provided
    const { data: profile } = await supabase
      .from("userprofile")
      .select("current_phase, gems")
      .eq("userid", userId)
      .single();

    const currentPhase = phaseId || profile.current_phase || 1; 
    const now = new Date().toISOString();
    const validUntil = new Date(Date.now() + 24 * 3600 * 1000).toISOString();

    // Fetch a random task for the given phase
    const { data: tasks, error } = await supabase
    .from("bonus_tasks")
    .select("id, description")
    .eq("current_phase", currentPhase)
    .order("id", { ascending: true }) 
    .limit(1);

    if (error) throw error;
    const task = tasks[0];

    // Check if the user has enough gems
    if (profile.gems < 50) {
      return res.status(400).json({ error: "Not enough gems." });
    }

    // Deduct gems and set bonus unlocked time
    await supabase
      .from("userprofile")
      .update({
        gems: profile.gems - 50,
        bonus_unlocked_at: now,
        bonus_valid_until: validUntil,
        bonus_used: false,
        bonus_task_id: task.id  
      })
      .eq("userid", userId);

    res.json({
      newGems: profile.gems - 50,
      bonus_task_id: task.id,
      bonus_task_description: task.description,
      bonus_unlocked_at: now,
      bonus_valid_until: validUntil
    });
  } catch (err) {
    console.error("unlockBonus error:", err);
    return res.status(500).json({ error: err.message });
  }
});

app.get("/api/bonusStatus", verifyToken, async (req, res) => {
  const userId = req.user.id;
  try {
    // fetch profile
    const { data: prof, error: profErr } = await supabase
      .from("userprofile")
      .select("gems, bonus_valid_until, bonus_used, bonus_task_id, current_phase")
      .eq("userid", userId)
      .single();
    if (profErr) throw profErr;

    // if there’s a task assigned, fetch its description
    let taskDesc = null;
    if (prof.bonus_task_id) {
      const { data: task, error: taskErr } = await supabase
        .from("bonus_tasks")
        .select("description")
        .eq("id", prof.bonus_task_id)
        .single();
      if (taskErr) throw taskErr;
      taskDesc = task.description;
    }

    res.json({
      gems: prof.gems,
      unlocked: !!(prof.bonus_valid_until && !prof.bonus_used && new Date(prof.bonus_valid_until) > new Date()),
      validUntil: prof.bonus_valid_until,
      bonusUsed: prof.bonus_used,
      phase: prof.current_phase,
      bonusTaskId: prof.bonus_task_id,
      bonusTaskDescription: taskDesc
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});


app.post("/api/logBonusMission", verifyToken, async (req, res) => {
  const userId = req.user.id;
  const { result } = req.body;
  
  try {
    const { data, error } = await supabase
      .from("userprofile")
      .update({ bonus_used: true })  
      .eq("userid", userId);
    
    if (error) throw error;

    res.json({ success: true });
  } catch (err) {
    console.error("logBonusMission error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/currentPhase", verifyToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const { data: prog, error: progErr } = await supabase
      .from("userprogress")
      .select("taskdetailsid")
      .eq("userid", userId)
      .order("created_at", { ascending: false })
      .limit(1)
      .single();
    if (progErr) throw progErr;
    if (!prog) return res.status(404).json({ error: "No progress found." });

    // 2) fetch that taskdetails row to get its phaseid
    const { data: detail, error: detErr } = await supabase
      .from("taskdetails")
      .select("phaseid")
      .eq("taskdetailsid", prog.taskdetailsid)
      .single();
    if (detErr) throw detErr;
    if (!detail) return res.status(404).json({ error: "Task details not found." });

    return res.json({ phase: detail.phaseid });
  } catch (err) {
    console.error("GET /api/currentPhase error:", err);
    return res.status(500).json({ error: err.message });
  }
});

app.get("/api/getTaskById/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("bonus_tasks")
      .select("id, description")
      .eq("id", id)
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error("getTaskById error:", err);
    res.status(500).json({ error: err.message });
  }
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


// Utility: generate 4-digit OTP
function generateOTP() {
  return Math.floor(1000 + Math.random() * 9000).toString(); // "1000" -> "9999"
}

// ---------------- CREATE ACCOUNT ----------------
app.post("/api/createAccount", async (req, res) => {
  const { email, password, timezone } = req.body;

  try {
    console.log("Attempting to create account for:", email);

    // 1) Check if user already exists
    const { data: existingUsers, error: checkError } = await supabase
      .from("userprofile")
      .select("email")
      .eq("email", email);

    if (checkError) throw checkError;
    if (existingUsers && existingUsers.length > 0) {
      console.log("User already exists:", email);
      return res.status(400).json({ message: "User already exists!" });
    }

    // 2) Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // 3) Generate a 4-digit OTP + expiry
    const otpCode = generateOTP();  // e.g. “1234”
    const otpExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes from now

    console.log("Inserting new user with is_verified=false & storing OTP...");

    // 4) Insert new user row
    const { data: newUser, error } = await supabase
      .from("userprofile")
      .insert({
        email,
        password: hashedPassword,
        timezone,
        created_at: new Date().toISOString(),
        is_verified: false,
        otp_code: otpCode,
        otp_expires: otpExpires.toISOString(),
      })
      .select()
      .single();

    if (error) {
      console.error("Error inserting user:", error);
      throw error;
    }
    if (!newUser) {
      throw new Error("User created but not returned from DB");
    }

    console.log("New user created:", newUser.email);

    // 5) Send OTP via email
    await transporter.sendMail({
      from: process.env.ZOHO_USER,  // e.g. "support@gritfit.site"
      to: newUser.email,
      subject: "Verify Your GritFit Account",
      text: `Hi there! Your GritFit account verification code is: ${otpCode}. It is valid for the next 15 minutes. For security reasons, never share this OTP with anyone. If you didn’t request this, feel free to ignore this message. Stay fit, stay safe!`,
    });

    // 6) Return partial success => user must verify next
    // NOTE: No token generation here; user is still “unverified.”
    return res.status(201).json({
      message: "User created. Please check your email for the OTP.",
    });
  } catch (error) {
    console.error("Error creating user:", error);
    return res.status(500).json({ 
      message: "Error creating account",
      error: error.message 
    });
  }
});


// POST /api/verifyOTP
app.post("/api/verifyOTP", async (req, res) => {
  const { email, code } = req.body;

  try {
    // 1) Find user
    const { data: users, error } = await supabase
      .from("userprofile")
      .select("*")
      .eq("email", email);

    if (error) throw error;
    if (!users || users.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = users[0];
    if (user.is_verified) {
      return res.status(200).json({ message: "Already verified. You can sign in." });
    }

    // 2) Check OTP
    if (!user.otp_code || !user.otp_expires) {
      return res.status(400).json({ message: "No OTP code on file" });
    }
    if (user.otp_code !== code) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // 3) Check expiration
    const now = new Date();
    const expires = new Date(user.otp_expires);
    if (now > expires) {
      return res.status(400).json({ message: "OTP expired" });
    }

    // 4) Mark user as verified, clear OTP
    const { error: updateErr } = await supabase
      .from("userprofile")
      .update({ 
        is_verified: true, 
        otp_code: null, 
        otp_expires: null 
      })
      .eq("email", email);

    if (updateErr) throw updateErr;

    // 5) Generate a token for immediate login
    const tokens = generateTokens({ id: user.userid, email: user.email });

    // If you want a refresh token cookie
    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    });

    return res.status(200).json({
      message: "Email verified successfully",
      token: tokens.accessToken,
    });
  } catch (err) {
    console.error("Error verifying OTP:", err);
    res.status(500).json({ message: "Error verifying OTP", error: err.message });
  }
});

function generateResetCode() {
  return Math.floor(1000 + Math.random() * 9000).toString(); 
}

app.post("/api/forgotPassword", async (req, res) => {
  const { email } = req.body;
  try {
    // 1) Check if user exists
    const { data: users, error } = await supabase
      .from("userprofile")
      .select("*")
      .eq("email", email)
      .single();

    if (error && error.code !== "PGRST116") throw error;
    if (!users) {
      return res.status(404).json({ message: "No user found with that email." });
    }

    // 2) Generate code + expiry
    const resetCode = generateResetCode();
    const expiresAt = new Date(Date.now() + 15 * 60_000); // 15 minutes

    // 3) Store in DB
    const { error: updError } = await supabase
      .from("userprofile")
      .update({
        reset_code: resetCode,
        reset_expires: expiresAt.toISOString(),
      })
      .eq("email", email);

    if (updError) throw updError;

    // 4) Send code via email
    await transporter.sendMail({
      from: process.env.ZOHO_USER,
      to: email,
      subject: "GritFit Password Reset",
      text: `Hello!\n\nYou requested a password reset. Your reset code is: ${resetCode}\nIt expires in 15 minutes. Never share this code with anyone.\n\n- GritFit Team`,
    });

    return res.status(200).json({
      message: "Reset code sent. Please check your email.",
    });
  } catch (err) {
    console.error("forgotPassword error:", err);
    return res.status(500).json({ message: "Failed to send reset code." });
  }
});

app.post("/api/resetPassword", async (req, res) => {
  const { email, resetCode, newPassword } = req.body;

  try {
    // 1) Find user by email
    const { data: users, error } = await supabase
      .from("userprofile")
      .select("*")
      .eq("email", email);

    if (error) throw error;
    if (!users || users.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = users[0];

    // 2) Check if reset code and expiration time exist
    if (!user.reset_code || !user.reset_expires) {
      return res.status(400).json({ message: "No reset code on file" });
    }

    // 3) Compare the reset code
    if (String(user.reset_code) !== String(resetCode)) {
      return res.status(400).json({ message: "Invalid reset code" });
    }

    // 4) Check if the reset code has expired
    const now = new Date().toISOString();
    const expires = new Date(user.reset_expires); // Parse reset_expires as a Date object
    if (now > expires) {
      return res.status(400).json({ message: "Reset code expired" });
    }

    // 5) Hash the new password
    const saltRounds = 10;
    const hashedNew = await bcrypt.hash(newPassword, saltRounds);

    // 6) Update the user's password and clear the reset code
    const { error: updateErr } = await supabase
      .from("userprofile")
      .update({
        password: hashedNew,
        reset_code: null,
        reset_expires: null,
      })
      .eq("email", email);

    if (updateErr) throw updateErr;

    return res.status(200).json({ message: "Password updated successfully!" });
  } catch (err) {
    console.error("Error in reset password:", err);
    return res.status(500).json({ message: "Server error" });
  }
});


// ---------------- SIGN IN (check is_verified) ----------------
app.post("/api/signIn", async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1) fetch user
    const { data: users, error } = await supabase
      .from("userprofile")
      .select("*")
      .eq("email", email);

    if (error) throw error;
    if (!users || users.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = users[0];

    // 2) check verified
    if (!user.is_verified) {
      return res
        .status(403)
        .json({ message: "Account not verified. Please check your email for OTP." });
    }

    // 3) check password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // 4) generate tokens
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
      .select("username, email, avatar_color , gems, bonus_used, bonus_task_id, current_phase")
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
      avatar_color: data.avatar_color,
      
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

// Import moment-timezone at the top
const moment = require("moment-timezone");

app.post("/api/userprogressNC", verifyToken, async (req, res) => {
  const userId = req.user.id;
  const { phaseId, taskId, reasonForNonCompletion, failedGoal } = req.body;

  if (!phaseId || !taskId || !reasonForNonCompletion) {
    return res.status(400).json({
      message: "Required fields missing: phaseId, taskId, reasonForNonCompletion",
    });
  }

  try {
    // 1) Find the current row in taskdetails
    const { data: currentTask, error: taskError } = await supabase
      .from("taskdetails")
      .select("*")
      .eq("phaseid", phaseId)
      .eq("taskid", taskId)
      .single();

    if (taskError || !currentTask) {
      return res.status(404).json({ message: "Task details not found" });
    }

    // 2) Mark current task as "Not Completed"
    const { error: updateError } = await supabase
      .from("userprogress")
      .update({
        taskstatus: "Not Completed",
        completion_date: new Date().toISOString(),
        notcompletionreason: reasonForNonCompletion,
        whichgoal: failedGoal && phaseId === 3 ? failedGoal : null,
      })
      .eq("taskdetailsid", currentTask.taskdetailsid)
      .eq("userid", userId);

    if (updateError) {
      console.error("Failed to mark task as Not Completed:", updateError);
      return res.status(500).json({ message: "Failed to update task status." });
    }

    // 3) Check cheat usage (for Phase 1 or 2)
    const { data: cheatCheck, error: cheatCheckError } = await supabase
      .from("user_phase_cheat_tracker")
      .select("cheat_used")
      .eq("userid", userId)
      .eq("phaseid", phaseId)
      .single();

    if (cheatCheckError && cheatCheckError.code !== "PGRST116") {
      console.error("Failed to check phase cheat status:", cheatCheckError);
      return res.status(500).json({ message: "Failed to check cheat day status." });
    }
    const cheatUsed = cheatCheck?.cheat_used || false;

    // 4) [NEW] fetch user timezone, schedule tomorrow midnight local
    const { data: userProfile, error: userProfileErr } = await supabase
      .from("userprofile")
      .select("timezone")
      .eq("userid", userId)
      .single();

    if (userProfileErr) {
      console.error("Failed to fetch user timezone:", userProfileErr);
      return res.status(500).json({ message: "Failed to fetch user timezone." });
    }
    const userTz = userProfile?.timezone || "UTC";

    const nowInTz = moment().tz(userTz);
    const tomorrowMidnightInTz = nowInTz.clone().add(1, "day").startOf("day");
    const nextActivationDate = tomorrowMidnightInTz.utc().toDate();

    // 5) If cheat not used => skip forward one day for Phase 1 or 2
    if ((phaseId === 1 || phaseId === 2) && !cheatUsed) {
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
          created_at: new Date().toISOString(),
        });

      if (insertNextTaskError) {
        console.error("Failed to insert next task after cheat day:", insertNextTaskError);
        return res.status(500).json({ message: "Failed to insert next task." });
      }

      // record cheat usage
      await supabase
        .from("user_phase_cheat_tracker")
        .upsert([
          {
            userid: userId,
            phaseid: phaseId,
            cheat_used: true,
            created_at: new Date().toISOString(),
          },
        ]);

      return res.status(200).json({ message: "Cheat day used - moved to next task." });

    } else if (phaseId === 1 || phaseId === 2) {
      // cheat used => reinsert same task
      const { error: repeatInsertError } = await supabase
        .from("userprogress")
        .insert({
          userid: userId,
          taskdetailsid: currentTask.taskdetailsid,
          taskstatus: "Not Started",
          task_activation_date: nextActivationDate.toISOString(),
          created_at: new Date().toISOString(),
        });

      if (repeatInsertError) {
        console.error("Failed to reinsert same task after cheat exhausted:", repeatInsertError);
        return res.status(500).json({ message: "Failed to reschedule task." });
      }

      return res.status(200).json({ message: "Cheat already used - retry same task." });

    } else {
      // Phase 3+ => always re-insert same task
      const { error: normalRetryInsertError } = await supabase
        .from("userprogress")
        .insert({
          userid: userId,
          taskdetailsid: currentTask.taskdetailsid,
          taskstatus: "Not Started",
          task_activation_date: nextActivationDate.toISOString(),
          created_at: new Date().toISOString(),
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
    let phaseId = parseInt(rawPhase, 10);
    let taskId = parseInt(rawTask, 10);

    console.log("[userprogressC] Completing (phase=", phaseId, ", task=", taskId, ")");

    // 1) Fetch user's time zone
    const { data: userProfile, error: userProfileErr } = await supabase
      .from("userprofile")
      .select("timezone")
      .eq("userid", userId)
      .single();

    if (userProfileErr) {
      console.error("[userprogressC] Failed to fetch user timezone:", userProfileErr);
      return res.status(500).json({ message: "Failed to fetch user timezone." });
    }
    const userTz = userProfile?.timezone || "UTC";
    console.log("[userprogressC] Using userTz =", userTz);

    // 2) Find current row in taskdetails
    const { data: currentTask, error: taskError } = await supabase
      .from("taskdetails")
      .select("*")
      .eq("phaseid", phaseId)
      .eq("taskid", taskId)
      .single();

    if (taskError || !currentTask) {
      console.error("[userprogressC] Current task not found");
      return res.status(404).json({ message: "Current task not found" });
    }

    // 3) Mark current task as Completed
    const { error: updateError } = await supabase
      .from("userprogress")
      .update({
        taskstatus: "Completed",
        completion_date: new Date().toISOString(),
      })
      .eq("taskdetailsid", currentTask.taskdetailsid)
      .eq("userid", userId);

    if (updateError) {
      console.error("[userprogressC] Error marking task completed:", updateError);
      return res.status(500).json({ message: "Failed to update task status." });
    }

    // 4) Determine next day/phase
    if (taskId < 5) {
      taskId += 1;
      console.log(`[userprogressC] Next day in same phase => (phase=${phaseId}, day=${taskId})`);
    } else {
      phaseId += 1;
      taskId = 1;
      console.log(`[userprogressC] Jumping to next phase => (phase=${phaseId}, day=1)`);
    }

    // 5) Fetch nextTask
    const { data: nextTask, error: nextTaskError } = await supabase
      .from("taskdetails")
      .select("*")
      .eq("phaseid", phaseId)
      .eq("taskid", taskId)
      .single();

    if (nextTaskError || !nextTask) {
      console.log("[userprogressC] No nextTask => all tasks done!");
      return res.status(200).json({ message: "All tasks done" });
    }

    // 6) Compute tomorrow local midnight => convert => store in UTC
    const nowInTz = moment().tz(userTz);
    const tomorrowMidnightInTz = nowInTz.clone().add(1, "day").startOf("day");
    const nextActivationDate = tomorrowMidnightInTz.utc().toDate();

    console.log("[userprogressC] Scheduling next day for user local midnight =>", nextActivationDate.toISOString());

    // 7) Insert next userprogress row
    const { error: insertError } = await supabase
      .from("userprogress")
      .insert({
        userid: userId,
        taskdetailsid: nextTask.taskdetailsid,
        taskstatus: "Not Started",
        task_activation_date: nextActivationDate.toISOString(),
        created_at: new Date().toISOString(),
      });

    if (insertError) {
      console.error("[userprogressC] Error inserting next userprogress:", insertError);
      return res.status(500).json({ message: "Failed to insert next userprogress" });
    }

    console.log(`[userprogressC] Inserted next day row => (phase=${phaseId}, task=${taskId}), activation=tomorrow local midnight`);
    return res.status(200).json({
      message: "Task completed. Next day set to tomorrow's local midnight.",
    });
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
