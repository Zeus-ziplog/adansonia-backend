import { Router } from 'express';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { prisma } from '../lib/prisma.js';
import dotenv from 'dotenv';

dotenv.config();

const router = Router();
const SECRET_KEY = process.env.JWT_SECRET || 'adansonia-secret-key-2024';
const ADMIN_FRONTEND_URL = process.env.ADMIN_FRONTEND_URL || 'https://adansonia-admin.vercel.app';

router.use(passport.initialize());

// Strategy Configuration
if (!passport._strategy('google')) {
  passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || "https://adansonia-backend.vercel.app/api/auth/google/callback",
    }, 
    async (_, __, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        if (!email) return done(null, false);
        
        // Timeout race: if DB takes > 4s, it's likely a 504 risk
        const admin = await Promise.race([
          prisma.admin.findUnique({ where: { email } }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('DB_TIMEOUT')), 4000))
        ]);
        
        return admin ? done(null, admin) : done(null, false);
      } catch (error) {
        console.error("Auth DB Error:", error);
        return done(null, false);
      }
    }
  ));
}

// --- EMERGENCY & DIRECT LOGIN ---
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Manual Override for the final week
  if (email === 'ziplogziki@gmail.com' && password === 'Adansonia2026!') {
    const token = jwt.sign({ email, role: 'admin' }, SECRET_KEY, { expiresIn: '7d' });
    return res.json({ token, email, avatar: '' });
  }

  res.status(401).json({ error: 'Please use Google Login or correct Emergency Credentials' });
});

// --- GOOGLE ROUTES ---
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'], session: false }));

router.get('/google/callback', (req, res, next) => {
  passport.authenticate('google', { session: false }, (err: any, admin: any) => {
    if (err || !admin) {
      return res.redirect(`${ADMIN_FRONTEND_URL}/login?error=unauthorized`);
    }

    const token = jwt.sign(
      { id: admin.id, email: admin.email, avatar: admin.avatar },
      SECRET_KEY,
      { expiresIn: '7d' }
    );

    const queryParams = new URLSearchParams({
      token,
      email: admin.email,
      avatar: admin.avatar || ''
    }).toString();

    res.redirect(`${ADMIN_FRONTEND_URL}/auth-success?${queryParams}`);
  })(req, res, next);
});

export default router;