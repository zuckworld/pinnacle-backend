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
import multer from 'multer';
import fs from 'fs';

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
  // Personal Information
  firstName: { type: String },
  lastName: { type: String },
  phoneNumber: { type: String },
  dateOfBirth: { type: Date },
  gender: { type: String },
  // Identity / KYC
  ssn: { type: String, sparse: true, unique: true },
  driversLicenseNumber: { type: String, sparse: true, unique: true },
  driversLicenseImage: { type: String },
  passportNumber: { type: String, sparse: true, unique: true },
  passportImage: { type: String },
  nationalIdNumber: { type: String, sparse: true, unique: true },
  nationalIdImage: { type: String },
  // Location
  country: { type: String },
  countryCode: { type: String },
  state: { type: String },
  city: { type: String },
  zipCode: { type: String },
  address: { type: String },
  // Financials
  balance: { type: Number, default: 0 },
  totalDeposit: { type: Number, default: 0 },
  totalWithdrawal: { type: Number, default: 0 },
  totalProfit: { type: Number, default: 0 },
  currentBalance: { type: Number, default: 0 },
  plan: { type: String, default: 'Starter' },
  // Admin controls
  accountStatus: { type: String, enum: ['pending','active','suspended','banned','deleted'], default: 'pending' },
  kycStatus: { type: String, enum: ['not_submitted','pending','approved','rejected'], default: 'not_submitted' },
  verifiedAt: { type: Date },
  lastLogin: { type: Date },
  registrationIP: { type: String },
  lastLoginIP: { type: String },
  notes: { type: String },
  isDeleted: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now }
},{ timestamps: true });

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
// serve uploaded KYC files
const uploadsPath = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsPath)) fs.mkdirSync(uploadsPath, { recursive: true });
app.use('/uploads', express.static(uploadsPath));
// Serve frontend static files from the sibling `frontend/` directory so
// the app and static assets share the same origin (prevents cross-site cookie issues during local dev).
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsPath);
  },
  filename: function (req, file, cb) {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const safe = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, `${unique}-${safe}`);
  }
});

const allowedUploadTypes = ['image/jpeg', 'image/png', 'image/jpg', 'image/gif', 'application/pdf'];
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!allowedUploadTypes.includes(file.mimetype)) {
      return cb(new Error('Only JPG, PNG, GIF, and PDF files are allowed.'));
    }
    cb(null, true);
  }
});

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

const phoneRegex = /^\+?[0-9\-\s]{7,20}$/;
const countryCodeRegex = /^[A-Z]{2}$/;
const validAccountStatuses = ['pending','active','suspended','banned','deleted'];
const validKycStatuses = ['not_submitted','pending','approved','rejected'];

const sanitizeUserForMe = (data) => ({
  id: data._id,
  username: data.username,
  email: data.email,
  role: data.role,
  firstName: data.firstName,
  lastName: data.lastName,
  phoneNumber: data.phoneNumber,
  country: data.country,
  countryCode: data.countryCode,
  state: data.state,
  city: data.city,
  zipCode: data.zipCode,
  address: data.address,
  totalDeposit: data.totalDeposit,
  totalWithdrawal: data.totalWithdrawal,
  totalProfit: data.totalProfit,
  currentBalance: data.currentBalance || data.balance,
  plan: data.plan,
  accountStatus: data.accountStatus,
  kycStatus: data.kycStatus,
  verifiedAt: data.verifiedAt,
  lastLogin: data.lastLogin,
  registrationIP: data.registrationIP,
  lastLoginIP: data.lastLoginIP,
  created_at: data.created_at,
  driversLicenseImage: data.driversLicenseImage,
  passportImage: data.passportImage,
  nationalIdImage: data.nationalIdImage,
});

const sanitizeUserForAdmin = (data) => ({
  id: data._id,
  username: data.username,
  email: data.email,
  role: data.role,
  firstName: data.firstName,
  lastName: data.lastName,
  phoneNumber: data.phoneNumber,
  country: data.country,
  countryCode: data.countryCode,
  state: data.state,
  city: data.city,
  zipCode: data.zipCode,
  address: data.address,
  totalDeposit: data.totalDeposit,
  totalWithdrawal: data.totalWithdrawal,
  totalProfit: data.totalProfit,
  currentBalance: data.currentBalance || data.balance,
  plan: data.plan,
  accountStatus: data.accountStatus,
  kycStatus: data.kycStatus,
  verifiedAt: data.verifiedAt,
  lastLogin: data.lastLogin,
  registrationIP: data.registrationIP,
  lastLoginIP: data.lastLoginIP,
  created_at: data.created_at,
  driversLicenseImage: data.driversLicenseImage,
  passportImage: data.passportImage,
  nationalIdImage: data.nationalIdImage,
  notes: data.notes,
});

app.patch('/api/auth/profile', authenticate, async (req, res) => {
  try {
    const allowed = ['firstName','lastName','phoneNumber','state','city','zipCode','address'];
    const updates = {};
    for (const key of allowed) {
      if (key in req.body) {
        updates[key] = req.body[key];
      }
    }
    if ('phoneNumber' in updates) {
      if (!phoneRegex.test(updates.phoneNumber)) {
        return res.status(400).json({ error: 'Phone number format is invalid.' });
      }
    }
    const user = await User.findByIdAndUpdate(req.user.id, updates, { new: true }).select('username email role firstName lastName phoneNumber country countryCode state city zipCode address totalDeposit totalWithdrawal totalProfit currentBalance plan accountStatus kycStatus verifiedAt lastLogin registrationIP lastLoginIP created_at driversLicenseImage passportImage nationalIdImage').exec();
    if (!user) return res.status(404).json({ error: 'User not found.' });
    return res.json({ user: sanitizeUserForMe(user) });
  } catch (error) {
    console.error('Profile update error', error);
    return res.status(500).json({ error: 'Unable to update profile.' });
  }
});

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
    // detect registration IP
    const registrationIP = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

    // try geolocation (best-effort)
    let country = '';
    let countryCode = '';
    try {
      const lookupIP = registrationIP.replace('::ffff:', '') || '';
      const geoRes = await fetch(`https://ipapi.co/${lookupIP}/json/`);
      if (geoRes.ok) {
        const geo = await geoRes.json();
        country = geo.country_name || '';
        countryCode = geo.country || '';
      }
    } catch (e) {
      console.warn('Geo lookup failed', e);
    }

    const newUser = await User.create({
      username: username.trim(),
      email: normalizedEmail,
      password_hash: passwordHash,
      registrationIP,
      country,
      countryCode,
      accountStatus: 'pending',
      kycStatus: 'not_submitted',
      currentBalance: 0,
      balance: 0
    });
    const token = createToken(newUser);
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    return res.json({ user: { id: newUser._id, username: newUser.username, email: newUser.email, role: newUser.role, currentBalance: newUser.currentBalance, plan: newUser.plan, country: newUser.country, countryCode: newUser.countryCode } });
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
    // update last login info
    const loginIP = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    user.lastLogin = new Date();
    user.lastLoginIP = loginIP;
    await user.save();

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
    return res.json({ user: { id: user._id, username: user.username, email: user.email, role: user.role, currentBalance: user.currentBalance || user.balance, plan: user.plan } });
  } catch (error) {
    console.error('Login error', error);
    return res.status(500).json({ error: 'Login failed.' });
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const data = await User.findById(req.user.id).select('username email role firstName lastName phoneNumber country countryCode state city zipCode address totalDeposit totalWithdrawal totalProfit currentBalance plan accountStatus kycStatus verifiedAt lastLogin registrationIP lastLoginIP created_at').exec();
    if (!data) return res.status(404).json({ error: 'User not found.' });
    return res.json({ user: { id: data._id, username: data.username, email: data.email, role: data.role, firstName: data.firstName, lastName: data.lastName, phoneNumber: data.phoneNumber, country: data.country, countryCode: data.countryCode, state: data.state, city: data.city, zipCode: data.zipCode, address: data.address, totalDeposit: data.totalDeposit, totalWithdrawal: data.totalWithdrawal, totalProfit: data.totalProfit, currentBalance: data.currentBalance || data.balance, plan: data.plan, accountStatus: data.accountStatus, kycStatus: data.kycStatus, verifiedAt: data.verifiedAt, lastLogin: data.lastLogin, registrationIP: data.registrationIP, lastLoginIP: data.lastLoginIP, created_at: data.created_at } });
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

// Admin: list users with pagination and search
app.get('/api/admin/users', authenticate, adminOnly, async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page || 1));
    const limit = Math.min(100, Number(req.query.limit || 20));
    const search = (req.query.search || '').trim();
    let filter = { isDeleted: false, role: { $ne: 'admin' } };
    if (search) {
      const re = new RegExp(search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter = {
        $and: [
          { isDeleted: false, role: { $ne: 'admin' } },
          { $or: [ { username: re }, { email: re }, { phoneNumber: re }, { country: re } ] }
        ]
      };
    }
    const total = await User.countDocuments(filter).exec();
    const users = await User.find(filter).select('firstName lastName username email phoneNumber country state currentBalance totalProfit totalDeposit totalWithdrawal kycStatus accountStatus created_at').sort({ created_at: -1 }).skip((page-1)*limit).limit(limit).exec();
    return res.json({ meta: { total, page, limit, pages: Math.ceil(total/limit) }, users: users.map(u => ({ id: u._id, fullName: `${u.firstName||''} ${u.lastName||''}`.trim(), username: u.username, email: u.email, phone: u.phoneNumber, country: u.country, state: u.state, balance: u.currentBalance || u.balance, profit: u.totalProfit, deposits: u.totalDeposit, withdrawals: u.totalWithdrawal, kycStatus: u.kycStatus, accountStatus: u.accountStatus, created_at: u.created_at })) });
  } catch (error) {
    console.error('Admin users error', error);
    return res.status(500).json({ error: 'Unable to load users.' });
  }
});

// Admin: get full user profile (includes sensitive fields)
app.get('/api/admin/users/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).exec();
    if (!user) return res.status(404).json({ error: 'User not found.' });
    return res.json({ user: sanitizeUserForAdmin(user) });
  } catch (error) {
    console.error('Admin user fetch error', error);
    return res.status(500).json({ error: 'Unable to load user.' });
  }
});

// Admin: patch user fields
app.patch('/api/admin/users/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const allowed = ['accountStatus','totalProfit','currentBalance','notes','kycStatus'];
    const updates = {};
    if ('accountStatus' in req.body) {
      if (!validAccountStatuses.includes(req.body.accountStatus)) {
        return res.status(400).json({ error: 'Invalid account status.' });
      }
      updates.accountStatus = req.body.accountStatus;
    }
    if ('kycStatus' in req.body) {
      if (!validKycStatuses.includes(req.body.kycStatus)) {
        return res.status(400).json({ error: 'Invalid KYC status.' });
      }
      updates.kycStatus = req.body.kycStatus;
    }
    if ('totalProfit' in req.body) {
      const profit = Number(req.body.totalProfit);
      if (Number.isNaN(profit)) return res.status(400).json({ error: 'totalProfit must be numeric.' });
      updates.totalProfit = profit;
    }
    if ('currentBalance' in req.body) {
      const balance = Number(req.body.currentBalance);
      if (Number.isNaN(balance)) return res.status(400).json({ error: 'currentBalance must be numeric.' });
      updates.currentBalance = balance;
    }
    if ('notes' in req.body) updates.notes = req.body.notes;
    const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).exec();
    if (!user) return res.status(404).json({ error: 'User not found.' });
    return res.json({ user: sanitizeUserForAdmin(user) });
  } catch (error) {
    console.error('Admin user update error', error);
    return res.status(500).json({ error: 'Unable to update user.' });
  }
});

// Admin: increase/decrease profit and optionally update balance
app.patch('/api/admin/users/:id/profit', authenticate, adminOnly, async (req, res) => {
  try {
    const { amount } = req.body;
    const parsed = Number(amount);
    if (Number.isNaN(parsed)) return res.status(400).json({ error: 'Amount must be numeric.' });
    const user = await User.findById(req.params.id).exec();
    if (!user) return res.status(404).json({ error: 'User not found.' });
    user.totalProfit = (user.totalProfit || 0) + parsed;
    // update balance if currentBalance is tracked
    user.currentBalance = (user.currentBalance || user.balance || 0) + parsed;
    await user.save();
    return res.json({ user });
  } catch (error) {
    console.error('Admin profit update error', error);
    return res.status(500).json({ error: 'Unable to update profit.' });
  }
});

// Admin: update location manually
app.patch('/api/admin/users/:id/location', authenticate, adminOnly, async (req, res) => {
  try {
    const allowed = ['country','countryCode','state','city','zipCode','address'];
    const updates = {};
    for (const key of allowed) if (key in req.body) updates[key] = req.body[key];
    const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).exec();
    if (!user) return res.status(404).json({ error: 'User not found.' });
    return res.json({ user });
  } catch (error) {
    console.error('Admin location update error', error);
    return res.status(500).json({ error: 'Unable to update location.' });
  }
});

// Admin: soft delete user
app.delete('/api/admin/users/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { isDeleted: true, accountStatus: 'deleted' }, { new: true }).exec();
    if (!user) return res.status(404).json({ error: 'User not found.' });
    return res.json({ message: 'User soft-deleted.' });
  } catch (error) {
    console.error('Admin delete error', error);
    return res.status(500).json({ error: 'Unable to delete user.' });
  }
});

// KYC upload for authenticated users
app.post('/api/auth/kyc-upload', authenticate, upload.fields([
  { name: 'driversLicense', maxCount: 1 },
  { name: 'passport', maxCount: 1 },
  { name: 'nationalId', maxCount: 1 }
]), async (req, res) => {
  try {
    const user = await User.findById(req.user.id).exec();
    if (!user) return res.status(404).json({ error: 'User not found.' });
    if (req.files && req.files.driversLicense && req.files.driversLicense[0]) user.driversLicenseImage = `/uploads/${req.files.driversLicense[0].filename}`;
    if (req.files && req.files.passport && req.files.passport[0]) user.passportImage = `/uploads/${req.files.passport[0].filename}`;
    if (req.files && req.files.nationalId && req.files.nationalId[0]) user.nationalIdImage = `/uploads/${req.files.nationalId[0].filename}`;
    // mark KYC submitted
    if (user.kycStatus === 'not_submitted') user.kycStatus = 'pending';
    await user.save();
    return res.json({ user });
  } catch (error) {
    console.error('KYC upload error', error);
    return res.status(500).json({ error: 'Unable to upload KYC files.' });
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
