const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
require("dotenv").config();

let cachedToken = null;
let expiresAt = 0;

async function getZohoAccessToken() {
  const now = Date.now();

  if (cachedToken && now < expiresAt - 30_000) {
    return cachedToken;
  }

  const res = await fetch("https://accounts.zoho.com/oauth/v2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      refresh_token: process.env.ZOHO_DESK_REFRESH,
      client_id: process.env.ZOHO_CLIENT_ID,
      client_secret: process.env.ZOHO_CLIENT_SECRET,
      grant_type: "refresh_token"
    }),
  });

  const json = await res.json();
  if (!json.access_token) {
    console.error("[Zoho] Token refresh failed:", json);
    throw new Error("Zoho Desk access token invalid");
  }

  cachedToken = json.access_token;
  expiresAt = now + json.expires_in * 1000;
  return cachedToken;
}

module.exports = { getZohoAccessToken };
