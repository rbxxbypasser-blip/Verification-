
const crypto = require("crypto");

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).send("Method not allowed");
  }

  const clientId = process.env.DISCORD_CLIENT_ID;

  if (!clientId) {
    return res.status(500).send("Discord configuration missing.");
  }

  const state = crypto.randomBytes(32).toString("hex");

  res.setHeader("Set-Cookie",
    `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
  );

  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    redirect_uri:
      "https://verification-pets.vercel.app/auth/discord/callback",
    scope: "identify guilds.join",
    state: state
  });

  return res.redirect(
    302,
    "https://discord.com/oauth2/authorize?" +
    params.toString()
  );
};
    
