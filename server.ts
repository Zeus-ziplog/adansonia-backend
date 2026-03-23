import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { PrismaClient } from '@prisma/client';

dotenv.config();

// ========== 1. PRISMA SERVERLESS OPTIMIZATION ==========
// This prevents "too many clients" errors during Vercel hot-reloads
const globalForPrisma = global as unknown as { prisma: PrismaClient };
export const prisma = globalForPrisma.prisma || new PrismaClient({
  log: ['error'],
});
if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;

const app = express();
const SECRET_KEY = process.env.JWT_SECRET || 'adansonia-secret-key-2024';
const ADMIN_FRONTEND_URL = process.env.ADMIN_FRONTEND_URL || 'http://localhost:5173';

// ========== 2. MIDDLEWARE ==========
app.use(cors({
  origin: [ADMIN_FRONTEND_URL, 'https://adansonia-admin.vercel.app'],
  credentials: true,
}));
app.use(express.json({ limit: '10mb' })); // 50mb is too heavy for serverless, 10mb is safer

// Passport Setup (Strictly Stateless)
app.use(passport.initialize());

// ========== 3. HELPERS (LAZY LOADED) ==========
const getCloudinary = async () => {
  const { v2: cloudinary } = await import('cloudinary');
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });
  return cloudinary;
};

const uploadToCloudinary = async (base64String: string, folder: string): Promise<string | null> => {
  try {
    const cloudinary = await getCloudinary();
    const uploadResponse = await cloudinary.uploader.upload(base64String, {
      folder: `adansonia/${folder}`,
    });
    return uploadResponse.secure_url;
  } catch (error) {
    console.error('Cloudinary error:', error);
    return null;
  }
};

// ========== 4. AUTH MIDDLEWARE ==========
const verifyToken = (req: Request, res: Response, next: NextFunction): void => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    res.status(401).json({ error: 'No token provided' });
    return;
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY) as any;
    (req as any).user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ========== 5. PASSPORT GOOGLE STRATEGY ==========
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
}, async (_accessToken, _refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value;
    if (!email) return done(null, false);

    let admin = await prisma.admin.findUnique({ where: { email } });
    if (!admin) return done(null, false); // Reject if not in DB

    const avatar = profile.photos?.[0]?.value;
    if (avatar && admin.avatar !== avatar) {
      admin = await prisma.admin.update({
        where: { id: admin.id },
        data: { avatar, googleId: profile.id },
      });
    }
    return done(null, admin);
  } catch (err) {
    return done(err as Error);
  }
}));

// ========== 6. ROUTES (CORE & DIAGNOSTIC) ==========
app.get('/', (req, res) => res.send('✅ Adansonia Backend Optimized (fra1)'));
app.get('/health', (req, res) => res.status(200).json({ status: 'OK' }));

// ========== 7. AUTH LOGIC ==========
app.post('/api/auth/login', async (req, res) => {
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

app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'], session: false }));

app.get('/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: `${ADMIN_FRONTEND_URL}/login?error=oauth_failed`, session: false }),
  (req, res) => {
    const user = req.user as any;
    const token = jwt.sign(
      { id: user.id, email: user.email, avatar: user.avatar },
      SECRET_KEY,
      { expiresIn: '7d' }
    );
    res.redirect(`${ADMIN_FRONTEND_URL}/login?token=${token}&email=${encodeURIComponent(user.email)}&avatar=${encodeURIComponent(user.avatar || '')}`);
  }
);

// ========== 8. ADMIN & STAFF MGMT ==========
app.post('/api/admin/register', verifyToken, async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = await prisma.admin.create({
      data: { email, password: hashedPassword, avatar: null },
    });
    res.json({ success: true, email: newAdmin.email });
  } catch (err) {
    res.status(500).json({ error: 'Admin creation failed' });
  }
});

app.get('/api/admin/staff', verifyToken, async (req, res) => {
  const staff = await prisma.staff.findMany({ orderBy: { priority: 'asc' } });
  res.json(staff);
});

app.post('/api/admin/staff', verifyToken, async (req, res) => {
  try {
    const { image_base64, ...data } = req.body;
    let image_url = '';
    if (image_base64) image_url = (await uploadToCloudinary(image_base64, 'staff')) || '';
    const newStaff = await prisma.staff.create({ data: { ...data, image_url } });
    res.json(newStaff);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create staff' });
  }
});

app.put('/api/admin/staff/:id', verifyToken, async (req, res) => {
  try {
    const { image_base64, ...rest } = req.body;
    let updateData = { ...rest };
    if (image_base64) {
      const url = await uploadToCloudinary(image_base64, 'staff');
      if (url) updateData.image_url = url;
    }
    const updated = await prisma.staff.update({ where: { id: req.params.id }, data: updateData });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

app.delete('/api/admin/staff/:id', verifyToken, async (req, res) => {
  await prisma.staff.delete({ where: { id: req.params.id } });
  res.json({ success: true });
});

// ========== 9. INSIGHTS & CASE STUDIES ==========
app.get('/api/insights', async (req, res) => {
  res.json(await prisma.insight.findMany({ orderBy: { published_date: 'desc' } }));
});

app.post('/api/admin/insights', verifyToken, async (req, res) => {
  try {
    const { image_base64, tags, ...data } = req.body;
    let image_url = '';
    if (image_base64) image_url = (await uploadToCloudinary(image_base64, 'insights')) || '';
    const insight = await prisma.insight.create({
      data: { ...data, image_url, tags: Array.isArray(tags) ? tags : [] }
    });
    res.json(insight);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create insight' });
  }
});

// ========== 10. AI ASSISTANT (LAZY IMPORT) ==========
app.post('/api/assistant', async (req, res) => {
  try {
    const { message } = req.body;
    const { default: Groq } = await import('groq-sdk');
    const groq = new Groq({ apiKey: process.env.GROQ_API_KEY! });

    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: 'You are a helpful assistant for Adansonia Law Firm. Respond in JSON with "action" and "answer" or "path".' },
        { role: 'user', content: message },
      ],
      response_format: { type: 'json_object' },
    });
    res.json(JSON.parse(completion.choices[0].message.content || '{}'));
  } catch (error) {
    res.status(500).json({ error: 'AI Error' });
  }
});

// ========== 11. EXPORTS ==========
// Critical for Vercel: Export the app directly
export default app;

if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`🚀 Local: http://localhost:${PORT}`));
}