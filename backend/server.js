require('dotenv').config();
const express = require('express');
const session = require('express-session');
const axios   = require('axios');
const cors    = require('cors');
const path    = require('path');   // 👈 ADD THIS

const app  = express();
const PORT = process.env.PORT || 3001;

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  SESSION_SECRET = 'change-me',
  REDIRECT_URI   = 'http://localhost:3001/auth/google/callback',
  FRONTEND_URL   = 'http://localhost:3001',   // 👈 SAME PORT NOW
} = process.env;

// ── Middleware ─────────────────────────────────────────────────
app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: false, maxAge: 86400000, sameSite: 'lax',},
}));

// 👇 ADD THIS — Serve frontend static files
app.use(express.static(path.join(__dirname, '../frontend')));

// ── Auth Guard ─────────────────────────────────────────────────
const requireAuth = (req, res, next) => {
  if (!req.session.user)
    return res.status(401).json({ error: 'Unauthorized' });
  next();
};

// ── Route 1: Redirect to Google ────────────────────────────────
app.get('/auth/google', (req, res) => {
  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.searchParams.set('client_id',     GOOGLE_CLIENT_ID);
  url.searchParams.set('redirect_uri',  REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope',         'openid email profile');
  url.searchParams.set('access_type',   'offline'); // get refresh_token
  url.searchParams.set('prompt',        'consent');
  res.redirect(url.toString());
});

// ── Route 2: OAuth2 Callback ───────────────────────────────────
app.get('/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.redirect(FRONTEND_URL + '/?error=' + error);

  try {
    // Exchange authorization code for tokens
    const { data: tokens } = await axios.post(
      'https://oauth2.googleapis.com/token',
      null,
      {
        params: {
          code,
          client_id:     GOOGLE_CLIENT_ID,
          client_secret: GOOGLE_CLIENT_SECRET,
          redirect_uri:  REDIRECT_URI,
          grant_type:    'authorization_code',
        },
      }
    );

    // Fetch user info using access_token
    const { data: user } = await axios.get(
      'https://www.googleapis.com/oauth2/v3/userinfo',
      { headers: { Authorization: 'Bearer ' + tokens.access_token } }
    );

    // Save to session (tokens stay server-side only)
    req.session.user   = user;
    req.session.tokens = tokens;

    res.redirect(FRONTEND_URL + '/profile.html');
  } catch (err) {
    console.error('OAuth error:', err.response?.data || err.message);
    res.redirect(FRONTEND_URL + '/?error=auth_failed');
  }
});

// ── Route 3: Get current user ──────────────────────────────────
app.get('/auth/me', (req, res) => {
  if (!req.session.user)
    return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: req.session.user });
});

// ── Route 4: Logout ────────────────────────────────────────────
app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

// ── Route 5: Protected API Example ────────────────────────────
app.get('/api/dashboard', requireAuth, (req, res) => {
  res.json({
    message : 'Welcome to your protected dashboard!',
    user    : req.session.user,
    loginAt : new Date().toISOString(),
  });
});

app.listen(PORT, () =>
  console.log('✅ Backend running at http://localhost:' + PORT)
);
