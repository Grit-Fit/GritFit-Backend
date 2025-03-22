// scheduler.js
const cron = require("node-cron");
const moment = require("moment-timezone");
const { createClient } = require("@supabase/supabase-js");
const axios = require("axios");


// Pusher credentials
const BEAMS_INSTANCE_ID = "ab36b7bc-d7f7-4be6-a812-afe25361ea37";
const BEAMS_SECRET_KEY = "C8A575AD252A83295B739D21D0EC072B6F3A00AE66D6FF7BD73D7F617A2032FC";

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_API_KEY);

// Runs every minute
cron.schedule("* * * * *", async () => {
  console.log("[scheduler] Cron job triggered at:", new Date().toISOString());

  try {
    // 1) Fetch only users who have beams_device_id (subscribed users)
    const { data: users, error } = await supabase
      .from("userprofile")
      .select("userid, timezone, beams_device_id")
      .not("beams_device_id", "is", null);

    if (error) {
      console.error("Error fetching users:", error);
      return;
    }
    if (!users || users.length === 0) {
      console.log("No subscribed users found.");
      return;
    }

    // 2) For each subscribed user, check local time
    for (const user of users) {
      if (!user.timezone) continue;

      let nowLocal;
      try {
        nowLocal = moment().tz(user.timezone);
      } catch (e) {
        console.log(`[scheduler] Invalid timezone for user ${user.userid}, skipping...`);
        continue;
      }

      if (!nowLocal || !nowLocal.isValid()) {
        console.log(`[scheduler] Invalid timezone for user ${user.userid}, skipping...`);
        continue;
      }

      const timeStr = nowLocal.format("HH:mm");
      console.log(`User ${user.userid} local time is ${timeStr}`);

      // Normal condition: send at 10 PM local time
      if (timeStr === "22:00") {
        console.log(`[scheduler] It's 10 PM for user ${user.userid}, sending push...`);
        const userInterest = `user-${user.userid}`;
        await publishToInterest(userInterest, {
          title: "Time to check in!",
          body: "Log in now and keep the momentum going!",
        });
      } else {
        // Uncomment these lines for testing every minute:
        
        // console.log(`[scheduler] TEST MODE: Sending push every minute to user ${user.userid}...`);
        // const userInterest = `user-${user.userid}`;
        // await publishToInterest(userInterest, {
        //   title: "Test Notification",
        //   body: `It's ${timeStr} in your timezone!`,
        // });
        
      }
    }
  } catch (err) {
    console.error("Cron job error:", err);
  }
});

// Helper function to publish to interest
async function publishToInterest(interest, { title, body }) {
  try {
    const url = `https://${BEAMS_INSTANCE_ID}.pushnotifications.pusher.com/publish_api/v1/instances/${BEAMS_INSTANCE_ID}/publishes/interests`;
    const response = await axios.post(
      url,
      {
        interests: [interest],
        web: {
          notification: { title, body },
        },
      },
      {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          Authorization: `Bearer ${BEAMS_SECRET_KEY}`,
        },
      }
    );
    console.log("[scheduler] Pusher publish success:", response.data);
  } catch (err) {
    console.error("[scheduler] Pusher publish error:", err.response?.data || err.message);
  }
}
