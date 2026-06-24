import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import mongoose from 'mongoose';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';
const PORT = process.env.PORT || 3000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'admin-secret-token';
// FRONTEND_ORIGIN may be a comma-separated list of allowed origins, e.g.
// FRONTEND_ORIGIN=http://localhost:51662,https://your-frontend.vercel.app
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '*';
const allowedOrigins = FRONTEND_ORIGIN.split(',').map(s => s.trim()).filter(Boolean);

if (!MONGODB_URI) {
  console.error('Missing MONGODB_URI in environment.');
  process.exit(1);
}

// Connect to MongoDB
mongoose.set('strictQuery', false);
mongoose
  .connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => {
    console.error('MongoDB connection error', err);
    process.exit(1);
  });

// Define User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  role: { type: String, default: 'user' },
  balance: { type: Number, default: 0 },
  plan: { type: String, default: 'Starter' },
  created_at: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

const app = express();
// Security headers: keep helmet protections but disable default CSP because
// the frontend uses inline scripts and CDN-loaded assets in development.
app.use(helmet({ contentSecurityPolicy: false }));

// Trust proxy so secure cookies and rate-limiting work behind proxies (Render, Vercel)
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// Rate limiter to protect from brute-force and abuse
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false });
app.use(limiter);

// CORS - allow specific origins. Use a dynamic origin function so the
// Access-Control-Allow-Origin header reflects the request origin when allowed.
const corsOptions = {
  origin: (origin, callback) => {
    // allow requests with no origin (e.g. curl, mobile apps)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes('*')) return callback(null, true);
    // compare origins exactly first
    if (allowedOrigins.includes(origin)) return callback(null, true);
    // allow any localhost origin if any localhost entry is allowed
    const isLocalhostOrigin = origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1');
    const allowedLocalhost = allowedOrigins.some((o) => o.includes('localhost') || o.includes('127.0.0.1'));
    if (isLocalhostOrigin && allowedLocalhost) return callback(null, true);
    // allow matching by hostname (ignore http/https mismatch during local dev)
    try {
      const reqHost = new URL(origin).host;
      for (const o of allowedOrigins) {
        try {
          const allowedHost = new URL(o).host;
          if (allowedHost === reqHost) return callback(null, true);
        } catch (e) {
          // allowed origin might be a host-only string
          if (o === reqHost) return callback(null, true);
        }
      }
    } catch (err) {
      // if origin is malformed, deny
    }
    return callback(null, false);
  },
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
// Serve frontend static files from the sibling `frontend/` directory so
// the app and static assets share the same origin (prevents cross-site cookie issues during local dev).
app.use(express.static(path.join(__dirname, '..', 'frontend')));

const createToken = (user) => {
  return jwt.sign({ id: user._id?.toString() || user.id, role: user.role }, JWT_SECRET, {
    expiresIn: '7d'
  });
};

const authenticate = (req, res, next) => {
  const token = (req.cookies && req.cookies.token) || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (process.env.NODE_ENV !== 'production') {
    try {
      console.log('[/api] authenticate middleware - incoming Cookie header:', req.headers.cookie);
    } catch (e) {}
  }
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

const adminOnly = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
};

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password || password.length < 8) {
    return res.status(400).json({ error: 'Username, email and password are required (password min 8 chars).' });
  }
  const normalizedEmail = email.trim().toLowerCase();
  try {
    const existing = await User.findOne({ $or: [{ email: normalizedEmail }, { username: username.trim() }] }).exec();
    if (existing) {
      if (existing.email === normalizedEmail) return res.status(409).json({ error: 'Email is already registered.' });
      return res.status(409).json({ error: 'Username is already taken.' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = await User.create({ username: username.trim(), email: normalizedEmail, password_hash: passwordHash });
    const token = createToken(newUser);
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    return res.json({ user: { id: newUser._id, username: newUser.username, email: newUser.email, role: newUser.role, balance: newUser.balance, plan: newUser.plan } });
  } catch (error) {
    console.error('Register error', error);
    return res.status(500).json({ error: 'Registration failed.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) return res.status(400).json({ error: 'Identifier and password are required.' });
  const trimmed = identifier.trim();
  const search = trimmed.includes('@') ? { email: trimmed.toLowerCase() } : { username: trimmed };
  try {
    const user = await User.findOne(search).exec();
    if (!user) return res.status(401).json({ error: 'Login failed. Check credentials.' });
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Login failed. Check credentials.' });
    const token = createToken(user);
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    // Development logging: print request origin/identifier and the Set-Cookie header
    if (process.env.NODE_ENV !== 'production') {
      try {
        console.log('[/api/auth/login] login successful for identifier:', trimmed);
        console.log('[/api/auth/login] request origin:', req.headers.origin || req.headers.referer || req.ip);
        const setCookieHeader = res.getHeader && res.getHeader('Set-Cookie');
        console.log('[/api/auth/login] Set-Cookie header:', setCookieHeader);
      } catch (e) {
        console.error('[/api/auth/login] logging failed', e);
      }
    }
    return res.json({ user: { id: user._id, username: user.username, email: user.email, role: user.role, balance: user.balance, plan: user.plan } });
  } catch (error) {
    console.error('Login error', error);
    return res.status(500).json({ error: 'Login failed.' });
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const data = await User.findById(req.user.id).select('username email role balance plan created_at').exec();
    if (!data) return res.status(404).json({ error: 'User not found.' });
    return res.json({ user: { id: data._id, username: data.username, email: data.email, role: data.role, balance: data.balance, plan: data.plan, created_at: data.created_at } });
  } catch (error) {
    console.error('Me error', error);
    return res.status(500).json({ error: 'Unable to load profile.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token', {
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  });
  res.json({ message: 'Logged out' });
});

app.get('/api/admin/users', authenticate, adminOnly, async (req, res) => {
  try {
    const users = await User.find().select('username email role balance plan created_at').sort({ created_at: -1 }).exec();
    return res.json({ users: users.map(u => ({ id: u._id, username: u.username, email: u.email, role: u.role, balance: u.balance, plan: u.plan, created_at: u.created_at })) });
  } catch (error) {
    console.error('Admin users error', error);
    return res.status(500).json({ error: 'Unable to load users.' });
  }
});

app.post('/api/admin/users/:id/balance', authenticate, adminOnly, async (req, res) => {
  const { id } = req.params;
  const { amount } = req.body;
  const parsedAmount = Number(amount);
  if (Number.isNaN(parsedAmount)) return res.status(400).json({ error: 'Amount must be a numeric value.' });
  try {
    const user = await User.findById(id).exec();
    if (!user) return res.status(404).json({ error: 'User not found.' });
    user.balance = Number(user.balance || 0) + parsedAmount;
    await user.save();
    return res.json({ user: { id: user._id, username: user.username, email: user.email, balance: user.balance, plan: user.plan } });
  } catch (error) {
    console.error('Balance update error', error);
    return res.status(500).json({ error: 'Unable to update user balance.' });
  }
});

app.post('/api/admin/users/:id/plan', authenticate, adminOnly, async (req, res) => {
  const { id } = req.params;
  const { plan } = req.body;
  if (!plan) return res.status(400).json({ error: 'Plan value is required.' });
  try {
    const user = await User.findById(id).exec();
    if (!user) return res.status(404).json({ error: 'User not found.' });
    user.plan = plan;
    await user.save();
    return res.json({ user: { id: user._id, username: user.username, email: user.email, role: user.role, balance: user.balance, plan: user.plan } });
  } catch (error) {
    console.error('Plan update error', error);
    return res.status(500).json({ error: 'Unable to update plan.' });
  }
});

app.post('/api/admin/setup', async (req, res) => {
  const secret = req.headers['x-admin-secret'];
  const { username, email, password } = req.body;
  if (secret !== ADMIN_SECRET) return res.status(403).json({ error: 'Invalid admin setup secret.' });
  if (!username || !email || !password || password.length < 8) return res.status(400).json({ error: 'Username, email and password are required (min 8 chars).' });
  const normalizedEmail = email.toLowerCase().trim();
  try {
    const existing = await User.findOne({ $or: [{ email: normalizedEmail }, { username: username.trim() }] }).exec();
    if (existing) {
      if (existing.email === normalizedEmail) return res.status(409).json({ error: 'Email is already registered.' });
      return res.status(409).json({ error: 'Username is already taken.' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const admin = await User.create({ username: username.trim(), email: normalizedEmail, password_hash: passwordHash, role: 'admin', balance: 0, plan: 'Admin' });
    return res.json({ user: { id: admin._id, username: admin.username, email: admin.email, role: admin.role, balance: admin.balance, plan: admin.plan } });
  } catch (error) {
    console.error('Admin setup failed', error);
    return res.status(500).json({ error: 'Admin setup failed.' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
