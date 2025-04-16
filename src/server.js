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
    // The user ID might come from your auth middleware
    const userId = req.user.id;  
    // If you don’t have a verifyToken, you could read from query or body:
    // const userId = req.query.userId; 

    // Fetch gems from the userprofile table
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
      .eq("userid", userId); 

    if (error) throw error;

    return res.json({ success: true, gems: newGemCount });
  } catch (err) {
    console.error("updateUserGems error:", err);
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/logBonusMission", verifyToken, async (req, res) => {
  try {
    const email = req.user.email; 
    const { result } = req.body; 
    if (!result || (result !== "reset" && result !== "tripled")) {
      return res.status(400).json({ error: "Invalid bonus mission result" });
    }
    
    const { error } = await supabase
      .from("userprofile")
      .update({ bonus_used: true })
      .eq("email", email);
    
    if (error) throw error;
    
    return res.status(200).json({ success: true });
  } catch (err) {
    console.error("logBonusMission error:", err);
    return res.status(500).json({ error: err.message });
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
      .select("username, email, avatar_color")
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
