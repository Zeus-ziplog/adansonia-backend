import { Router } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { prisma } from '../lib/prisma.js'; // Points to your consolidated prisma client
import dotenv from 'dotenv';

// 1. Initialize dotenv at the top level to ensure variables are available globally
dotenv.config();

const router = Router();
const SECRET_KEY = process.env.JWT_SECRET || 'adansonia-secret-key-2024';
const ADMIN_FRONTEND_URL = process.env.ADMIN_FRONTEND_URL || 'http://localhost:5173';

// 2. Configure Passport Strategy once at the top level to avoid re-initialization errors
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    // Explicitly define the callback to match your Google Cloud Console settings
    callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:5000/api/auth/google/callback",
  }, 
  async (_, __, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value;
      if (!email) return done(null, false);
      
      // Look up the user in your Supabase database via Prisma
      const admin = await prisma.admin.findUnique({ where: { email } });
      return admin ? done(null, admin) : done(null, false);
    } catch (error) {
      return done(error as Error, false);
    }
  }
));

// --- STANDARD LOGIN ---
router.post('/login', async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;
    const admin = await prisma.admin.findUnique({ where: { email } });
    
    if (!admin || !admin.password || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: admin.id, email: admin.email, avatar: admin.avatar },
      SECRET_KEY,
      { expiresIn: rememberMe ? '30d' : '7d' }
    );
    res.json({ token, email: admin.email, avatar: admin.avatar });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// --- GOOGLE AUTH INITIALIZATION ---
// Initiates the request to Google
router.get('/google', passport.authenticate('google', { 
  scope: ['profile', 'email'], 
  session: false 
}));

// --- GOOGLE AUTH CALLBACK ---
// Handles the successful return from Google
router.get('/google/callback', (req, res, next) => {
  passport.authenticate('google', { session: false }, (err: any, admin: any) => {
    if (err || !admin) {
      // Redirect back to login if the admin is not authorized in your database
      return res.redirect(`${ADMIN_FRONTEND_URL}/login?error=unauthorized`);
    }

    // Successfully found the admin; generate the access token
    const token = jwt.sign(
      { id: admin.id, email: admin.email, avatar: admin.avatar },
      SECRET_KEY,
      { expiresIn: '7d' }
    );

    // 3. FIX: Append email and avatar so AuthSuccess.tsx can parse them correctly
    const queryParams = new URLSearchParams({
      token,
      email: admin.email,
      avatar: admin.avatar || ''
    }).toString();

    res.redirect(`${ADMIN_FRONTEND_URL}/auth-success?${queryParams}`);
  })(req, res, next);
});

export default router;