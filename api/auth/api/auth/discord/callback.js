
const crypto = require("crypto");

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).send("Method not allowed");
  }

  const cookies = Object.fromEntries(
    (req.headers.cookie || "")
      .split(";")
      .map(c => c.trim().split(/=(.*)/s))
      .filter(c => c.length === 2)
  );

  const expectedState = cookies.oauth_state;
  const receivedState = req.query.state;
  const code = req.query.code;

  res.setHeader("Set-Cookie",
    "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
  );

  if (!expectedState || !receivedState ||
      expectedState !== receivedState || !code) {
    return res.status(400).send("Invalid authorization. Please try again.");
  }

  const {
    DISCORD_CLIENT_ID,
    DISCORD_CLIENT_SECRET,
    SESSION_SECRET
  } = process.env;

  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !SESSION_SECRET) {
    return res.status(500).send("Server configuration incomplete.");
  }

  try {
    const body = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri:
        "https://verification-pets.vercel.app/auth/discord/callback"
    });

    const tokenResponse = await fetch(
      "https://discord.com/api/v10/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body
      }
    );

    if (!tokenResponse.ok) {
      return res.status(400).send("Discord authorization failed.");
    }

    const token = await tokenResponse.json();

    const userResponse = await fetch(
      "https://discord.com/api/v10/users/@me",
      {
        headers: {
          Authorization: `Bearer ${token.access_token}`
        }
      }
    );

    if (!userResponse.ok) {
      return res.status(400).send("Could not confirm Discord account.");
    }

    const user = await userResponse.json();

    const session = Buffer.from(JSON.stringify({
      discordId: user.id,
      expires: Date.now() + 10 * 60 * 1000
    })).toString("base64url");

    const signature = crypto
      .createHmac("sha256", SESSION_SECRET)
      .update(session)
      .digest("base64url");

    res.setHeader("Set-Cookie", [
      "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
      `discord_session=${session}.${signature}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
    ]);

    return res.redirect(302, "/?discord=connected");

  } catch (error) {
    console.error("Discord OAuth error:", error);
    return res.status(500).send("Authorization could not be completed.");
  }
};
      
