import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import Groq from 'groq-sdk';
import dotenv from 'dotenv';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import serverless from 'serverless-http';
import { PrismaClient } from '@prisma/client';

dotenv.config();

const app = express();
const prisma = new PrismaClient();

// Test database connection immediately (logs to Vercel)
(async () => {
  try {
    await Promise.race([
      prisma.$connect(),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Connection timeout after 10 seconds')), 10000)
      )
    ]);
    console.log('✅ Prisma connected to Supabase');
  } catch (err) {
    console.error('❌ Prisma connection error:', err);
  }
})();

const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || 'adansonia-secret-key-2024';
const ADMIN_FRONTEND_URL = process.env.ADMIN_FRONTEND_URL || 'http://localhost:5173';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ========== Middleware ==========
app.use(cors());
app.use(express.json({ limit: '50mb' }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

app.use(passport.initialize());
app.use(passport.session());

// ========== TEST ROUTE ==========
app.get('/', (req, res) => {
  res.send('✅ Adansonia backend is live on Vercel!');
});

// Simple ping route to test function without DB
app.get('/ping', (req, res) => {
  res.send('pong');
});

// ========== Uploads directory – handle gracefully on Vercel ==========
const uploadsDir = path.join(__dirname, 'uploads');
try {
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log('✅ Uploads directory created at', uploadsDir);
  }
} catch (err) {
  console.warn('⚠️ Could not create uploads directory. File uploads will not work on Vercel.', err);
}
app.use('/uploads', express.static(uploadsDir));

// ========== Auth Middleware ==========
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

// ========== Google OAuth Strategy ==========
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:5000/api/auth/google/callback'
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      console.log('📩 Google OAuth profile received:', JSON.stringify(profile, null, 2));
      const email = profile.emails?.[0]?.value;
      const avatar = profile.photos?.[0]?.value;
      if (!email) {
        console.error('❌ No email in Google profile');
        return done(null, false, { message: 'No email from Google' });
      }

      let admin = await prisma.admin.findUnique({ where: { email } });
      if (!admin) {
        console.log('❓ No admin found for email:', email);
        return done(null, false, { message: 'Admin not found' });
      }

      if (!admin.avatar || admin.avatar !== avatar) {
        admin = await prisma.admin.update({
          where: { id: admin.id },
          data: { avatar, googleId: profile.id }
        });
        console.log('✏️ Updated admin with avatar/googleId:', admin.email);
      }

      console.log('✅ Admin authenticated:', admin.email);
      return done(null, admin);
    } catch (err) {
      console.error('🔥 Error in Google OAuth strategy:', err);
      return done(err as Error);
    }
  }
));

passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await prisma.admin.findUnique({ where: { id } });
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ========== AUTH ROUTES ==========
app.post('/api/auth/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, rememberMe } = req.body;

    const adminCount = await prisma.admin.count();
    if (adminCount === 0 && email === 'admin@adansonia.com' && password === 'password123') {
      const expiresIn = rememberMe ? '30d' : '7d';
      const token = jwt.sign({ id: 'initial', email }, SECRET_KEY, { expiresIn });
      res.json({ token, email });
      return;
    }

    const admin = await prisma.admin.findUnique({ where: { email } });
    if (!admin || !admin.password || !(await bcrypt.compare(password, admin.password))) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const expiresIn = rememberMe ? '30d' : '7d';
    const token = jwt.sign(
      { id: admin.id, email: admin.email, avatar: admin.avatar },
      SECRET_KEY,
      { expiresIn }
    );
    res.json({ token, email: admin.email, avatar: admin.avatar });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ========== GOOGLE OAUTH ROUTES ==========
app.get('/api/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/api/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: `${ADMIN_FRONTEND_URL}/login`,
    session: false 
  }),
  (req: Request, res: Response) => {
    try {
      const user = req.user as any;
      if (!user) {
        console.error('❌ No user after Google authentication');
        return res.status(500).json({ error: 'Authentication failed' });
      }
      const token = jwt.sign(
        { id: user.id, email: user.email, avatar: user.avatar },
        SECRET_KEY,
        { expiresIn: '7d' }
      );
      console.log('✅ Google OAuth success, redirecting to frontend with token');
      res.redirect(
        `${ADMIN_FRONTEND_URL}/login?token=${token}&email=${encodeURIComponent(user.email)}&avatar=${encodeURIComponent(user.avatar || '')}`
      );
    } catch (err) {
      console.error('🔥 Error in callback handler:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// ========== ADMIN MANAGEMENT ==========
app.post('/api/admin/register', verifyToken, async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const existing = await prisma.admin.findUnique({ where: { email } });
    if (existing) {
      return res.status(400).json({ error: 'Admin already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = await prisma.admin.create({
      data: {
        email,
        password: hashedPassword,
        created_at: new Date(),
        avatar: null
      }
    });

    res.json({ success: true, email: newAdmin.email });
  } catch (err) {
    console.error('Admin registration error:', err);
    res.status(500).json({ error: 'Failed to create admin' });
  }
});

app.get('/api/admin/admins', verifyToken, async (req: Request, res: Response) => {
  try {
    const admins = await prisma.admin.findMany({
      select: { id: true, email: true, avatar: true, created_at: true, googleId: true }
    });
    res.json(admins);
  } catch (err) {
    console.error('Fetch admins error:', err);
    res.status(500).json({ error: 'Failed to fetch admins' });
  }
});

app.delete('/api/admin/admins/:id', verifyToken, async (req: Request, res: Response) => {
  try {
    await prisma.admin.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete admin error:', err);
    res.status(500).json({ error: 'Failed to delete admin' });
  }
});

// ========== STAFF ROUTES ==========
app.get('/api/staff', async (req, res) => {
  try {
    const staff = await prisma.staff.findMany({
      orderBy: { priority: 'asc' }
    });
    res.json(staff);
  } catch (err) {
    console.error('Fetch staff error:', err);
    res.status(500).json({ error: 'Failed to fetch staff' });
  }
});

app.get('/api/staff/:id', async (req, res) => {
  try {
    const member = await prisma.staff.findUnique({ where: { id: req.params.id } });
    if (!member) return res.status(404).json({ error: 'Not found' });
    res.json(member);
  } catch (err) {
    console.error('Fetch staff by id error:', err);
    res.status(500).json({ error: 'Invalid ID or server error' });
  }
});

app.get('/api/admin/staff', verifyToken, async (req, res) => {
  try {
    const staff = await prisma.staff.findMany({
      orderBy: { priority: 'asc' }
    });
    res.json(staff);
  } catch (err) {
    console.error('Fetch admin staff error:', err);
    res.status(500).json({ error: 'Failed to fetch staff' });
  }
});

// Disable file upload endpoints on Vercel – they need cloud storage
const isVercel = process.env.VERCEL === '1';

app.post('/api/admin/staff', verifyToken, async (req, res) => {
  if (isVercel) {
    return res.status(501).json({ error: 'File uploads not supported on Vercel. Please use cloud storage.' });
  }
  try {
    const { name, email, image_base64, bio, priority, role, expertise } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });

    let imageUrl = '';
    if (image_base64?.includes('base64')) {
      const fileName = `advocate_${Date.now()}.png`;
      const base64Data = image_base64.replace(/^data:image\/\w+;base64,/, "");
      fs.writeFileSync(path.join(uploadsDir, fileName), base64Data, 'base64');
      imageUrl = `${req.protocol}://${req.get('host')}/uploads/${fileName}`;
    }

    const newStaff = await prisma.staff.create({
      data: {
        name,
        email,
        role,
        expertise: expertise || [],
        priority: priority || 0,
        image_url: imageUrl,
        bio
      }
    });
    res.json(newStaff);
  } catch (err) {
    console.error('Create staff error:', err);
    res.status(500).json({ error: 'Failed to create staff' });
  }
});

app.put('/api/admin/staff/:id', verifyToken, async (req, res) => {
  if (isVercel) {
    return res.status(501).json({ error: 'File uploads not supported on Vercel. Please use cloud storage.' });
  }
  try {
    const { image_base64, ...rest } = req.body;
    let imageUrl;
    if (image_base64?.includes('base64')) {
      const fileName = `advocate_${Date.now()}.png`;
      const base64Data = image_base64.replace(/^data:image\/\w+;base64,/, "");
      fs.writeFileSync(path.join(uploadsDir, fileName), base64Data, 'base64');
      imageUrl = `${req.protocol}://${req.get('host')}/uploads/${fileName}`;
    }

    const updateData: any = { ...rest };
    if (imageUrl) updateData.image_url = imageUrl;

    const updated = await prisma.staff.update({
      where: { id: req.params.id },
      data: updateData
    });
    res.json(updated);
  } catch (err) {
    console.error('Update staff error:', err);
    res.status(500).json({ error: 'Failed to update staff' });
  }
});

app.delete('/api/admin/staff/:id', verifyToken, async (req, res) => {
  try {
    await prisma.staff.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete staff error:', err);
    res.status(500).json({ error: 'Failed to delete staff' });
  }
});

// ========== TESTIMONIALS ROUTES ==========
app.get('/api/testimonials', async (req, res) => {
  try {
    const testimonials = await prisma.testimonial.findMany();
    res.json(testimonials);
  } catch (err) {
    console.error('Fetch testimonials error:', err);
    res.status(500).json({ error: 'Failed to fetch testimonials' });
  }
});

app.get('/api/testimonials/:id', async (req, res) => {
  try {
    const item = await prisma.testimonial.findUnique({ where: { id: req.params.id } });
    if (!item) return res.status(404).json({ error: 'Not found' });
    res.json(item);
  } catch (err) {
    console.error('Fetch testimonial by id error:', err);
    res.status(500).json({ error: 'Invalid ID' });
  }
});

app.get('/api/admin/testimonials', verifyToken, async (req, res) => {
  try {
    const testimonials = await prisma.testimonial.findMany();
    res.json(testimonials);
  } catch (err) {
    console.error('Fetch admin testimonials error:', err);
    res.status(500).json({ error: 'Failed to fetch testimonials' });
  }
});

app.post('/api/admin/testimonials', verifyToken, async (req, res) => {
  try {
    const { name, role, quote, avatar } = req.body;
    if (!name || !quote) return res.status(400).json({ error: 'Name and quote required' });
    const newItem = await prisma.testimonial.create({
      data: { name, role, quote, avatar }
    });
    res.json(newItem);
  } catch (err) {
    console.error('Create testimonial error:', err);
    res.status(500).json({ error: 'Failed to create testimonial' });
  }
});

app.put('/api/admin/testimonials/:id', verifyToken, async (req, res) => {
  try {
    const updated = await prisma.testimonial.update({
      where: { id: req.params.id },
      data: req.body
    });
    res.json(updated);
  } catch (err) {
    console.error('Update testimonial error:', err);
    res.status(500).json({ error: 'Failed to update testimonial' });
  }
});

app.delete('/api/admin/testimonials/:id', verifyToken, async (req, res) => {
  try {
    await prisma.testimonial.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete testimonial error:', err);
    res.status(500).json({ error: 'Failed to delete testimonial' });
  }
});

// ========== INSIGHTS ROUTES ==========
app.get('/api/insights', async (req, res) => {
  try {
    const insights = await prisma.insight.findMany({
      orderBy: { published_date: 'desc' }
    });
    res.json(insights);
  } catch (err) {
    console.error('Fetch insights error:', err);
    res.status(500).json({ error: 'Failed to fetch insights' });
  }
});

app.get('/api/insights/:id', async (req, res) => {
  try {
    const insight = await prisma.insight.findUnique({ where: { id: req.params.id } });
    if (!insight) return res.status(404).json({ error: 'Not found' });
    res.json(insight);
  } catch (err) {
    console.error('Fetch insight by id error:', err);
    res.status(500).json({ error: 'Invalid ID' });
  }
});

app.get('/api/admin/insights', verifyToken, async (req, res) => {
  try {
    const insights = await prisma.insight.findMany({
      orderBy: { published_date: 'desc' }
    });
    res.json(insights);
  } catch (err) {
    console.error('Fetch admin insights error:', err);
    res.status(500).json({ error: 'Failed to fetch insights' });
  }
});

app.post('/api/admin/insights', verifyToken, async (req, res) => {
  if (isVercel) {
    return res.status(501).json({ error: 'File uploads not supported on Vercel. Please use cloud storage.' });
  }
  try {
    const { title, content, published_date, published, category, tags, image_base64 } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'Title and content required' });

    let imageUrl = '';
    if (image_base64?.includes('base64')) {
      const fileName = `insight_${Date.now()}.png`;
      const base64Data = image_base64.replace(/^data:image\/\w+;base64,/, "");
      fs.writeFileSync(path.join(uploadsDir, fileName), base64Data, 'base64');
      imageUrl = `${req.protocol}://${req.get('host')}/uploads/${fileName}`;
    }

    const newInsight = await prisma.insight.create({
      data: {
        title,
        content,
        published_date: published_date ? new Date(published_date) : new Date(),
        published: published !== undefined ? published : true,
        category: category || '',
        tags: tags ? (Array.isArray(tags) ? tags : tags.split(',').map((t: string) => t.trim())) : [],
        image_url: imageUrl
      }
    });
    res.json(newInsight);
  } catch (err) {
    console.error('Create insight error:', err);
    res.status(500).json({ error: 'Failed to create insight' });
  }
});

app.put('/api/admin/insights/:id', verifyToken, async (req, res) => {
  if (isVercel) {
    return res.status(501).json({ error: 'File uploads not supported on Vercel. Please use cloud storage.' });
  }
  try {
    const { image_base64, ...rest } = req.body;
    let imageUrl;
    if (image_base64?.includes('base64')) {
      const fileName = `insight_${Date.now()}.png`;
      const base64Data = image_base64.replace(/^data:image\/\w+;base64,/, "");
      fs.writeFileSync(path.join(uploadsDir, fileName), base64Data, 'base64');
      imageUrl = `${req.protocol}://${req.get('host')}/uploads/${fileName}`;
    }

    const updateData: any = { ...rest };
    if (imageUrl) updateData.image_url = imageUrl;

    const updated = await prisma.insight.update({
      where: { id: req.params.id },
      data: updateData
    });
    res.json(updated);
  } catch (err) {
    console.error('Update insight error:', err);
    res.status(500).json({ error: 'Failed to update insight' });
  }
});

app.delete('/api/admin/insights/:id', verifyToken, async (req, res) => {
  try {
    await prisma.insight.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete insight error:', err);
    res.status(500).json({ error: 'Failed to delete insight' });
  }
});

// ========== CAPABILITIES ROUTES ==========
app.get('/api/capabilities', async (req, res) => {
  try {
    const caps = await prisma.capability.findMany({
      orderBy: { priority: 'asc' }
    });
    res.json(caps);
  } catch (err) {
    console.error('Fetch capabilities error:', err);
    res.status(500).json({ error: 'Failed to fetch capabilities' });
  }
});

app.get('/api/capabilities/:id', async (req, res) => {
  try {
    const item = await prisma.capability.findUnique({ where: { id: req.params.id } });
    if (!item) return res.status(404).json({ error: 'Not found' });
    res.json(item);
  } catch (err) {
    console.error('Fetch capability by id error:', err);
    res.status(500).json({ error: 'Invalid ID' });
  }
});

app.get('/api/admin/capabilities', verifyToken, async (req, res) => {
  try {
    const caps = await prisma.capability.findMany({
      orderBy: { priority: 'asc' }
    });
    res.json(caps);
  } catch (err) {
    console.error('Fetch admin capabilities error:', err);
    res.status(500).json({ error: 'Failed to fetch capabilities' });
  }
});

app.post('/api/admin/capabilities', verifyToken, async (req, res) => {
  try {
    const { title, description, icon, priority } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    const newItem = await prisma.capability.create({
      data: { title, description, icon, priority: priority || 0 }
    });
    res.json(newItem);
  } catch (err) {
    console.error('Create capability error:', err);
    res.status(500).json({ error: 'Failed to create capability' });
  }
});

app.put('/api/admin/capabilities/:id', verifyToken, async (req, res) => {
  try {
    const updated = await prisma.capability.update({
      where: { id: req.params.id },
      data: req.body
    });
    res.json(updated);
  } catch (err) {
    console.error('Update capability error:', err);
    res.status(500).json({ error: 'Failed to update capability' });
  }
});

app.delete('/api/admin/capabilities/:id', verifyToken, async (req, res) => {
  try {
    await prisma.capability.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete capability error:', err);
    res.status(500).json({ error: 'Failed to delete capability' });
  }
});

// ========== CASE STUDIES ROUTES ==========
app.get('/api/case-studies', async (req, res) => {
  try {
    const studies = await prisma.caseStudy.findMany();
    res.json(studies);
  } catch (err) {
    console.error('Fetch case studies error:', err);
    res.status(500).json({ error: 'Failed to fetch case studies' });
  }
});

app.get('/api/case-studies/:id', async (req, res) => {
  try {
    const item = await prisma.caseStudy.findUnique({ where: { id: req.params.id } });
    if (!item) return res.status(404).json({ error: 'Not found' });
    res.json(item);
  } catch (err) {
    console.error('Fetch case study by id error:', err);
    res.status(500).json({ error: 'Invalid ID' });
  }
});

app.get('/api/admin/case-studies', verifyToken, async (req, res) => {
  try {
    const studies = await prisma.caseStudy.findMany();
    res.json(studies);
  } catch (err) {
    console.error('Fetch admin case studies error:', err);
    res.status(500).json({ error: 'Failed to fetch case studies' });
  }
});

app.post('/api/admin/case-studies', verifyToken, async (req, res) => {
  if (isVercel) {
    return res.status(501).json({ error: 'File uploads not supported on Vercel. Please use cloud storage.' });
  }
  try {
    const { title, description, practiceArea, image_base64, client, outcome } = req.body;
    if (!title || !description) return res.status(400).json({ error: 'Title and description required' });

    let imageUrl = '';
    if (image_base64?.includes('base64')) {
      const fileName = `casestudy_${Date.now()}.png`;
      const base64Data = image_base64.replace(/^data:image\/\w+;base64,/, "");
      fs.writeFileSync(path.join(uploadsDir, fileName), base64Data, 'base64');
      imageUrl = `${req.protocol}://${req.get('host')}/uploads/${fileName}`;
    }

    const newItem = await prisma.caseStudy.create({
      data: {
        title,
        description,
        practiceArea,
        image_url: imageUrl,
        client,
        outcome
      }
    });
    res.json(newItem);
  } catch (err) {
    console.error('Create case study error:', err);
    res.status(500).json({ error: 'Failed to create case study' });
  }
});

app.put('/api/admin/case-studies/:id', verifyToken, async (req, res) => {
  if (isVercel) {
    return res.status(501).json({ error: 'File uploads not supported on Vercel. Please use cloud storage.' });
  }
  try {
    const { image_base64, ...rest } = req.body;
    let imageUrl;
    if (image_base64?.includes('base64')) {
      const fileName = `casestudy_${Date.now()}.png`;
      const base64Data = image_base64.replace(/^data:image\/\w+;base64,/, "");
      fs.writeFileSync(path.join(uploadsDir, fileName), base64Data, 'base64');
      imageUrl = `${req.protocol}://${req.get('host')}/uploads/${fileName}`;
    }

    const updateData: any = { ...rest };
    if (imageUrl) updateData.image_url = imageUrl;

    const updated = await prisma.caseStudy.update({
      where: { id: req.params.id },
      data: updateData
    });
    res.json(updated);
  } catch (err) {
    console.error('Update case study error:', err);
    res.status(500).json({ error: 'Failed to update case study' });
  }
});

app.delete('/api/admin/case-studies/:id', verifyToken, async (req, res) => {
  try {
    await prisma.caseStudy.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete case study error:', err);
    res.status(500).json({ error: 'Failed to delete case study' });
  }
});

// ========== CONTACT MESSAGES ROUTES ==========
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    if (!name || !email || !message) return res.status(400).json({ error: 'Missing fields' });
    const newMessage = await prisma.contactMessage.create({
      data: { name, email, message }
    });
    res.json({ success: true, id: newMessage.id });
  } catch (err) {
    console.error('Contact form error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.get('/api/admin/contact', verifyToken, async (req, res) => {
  try {
    const messages = await prisma.contactMessage.findMany({
      orderBy: { created_at: 'desc' }
    });
    res.json(messages);
  } catch (err) {
    console.error('Fetch messages error:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.delete('/api/admin/contact/:id', verifyToken, async (req, res) => {
  try {
    await prisma.contactMessage.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete message error:', err);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// ========== AI ASSISTANT ==========
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY! });

app.post('/api/assistant', async (req: Request, res: Response) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });

    const systemPrompt = `
You are a helpful assistant for the law firm "Adansonia Kiamba Mbithi & Co. Advocates". 
Answer the user's question using your general knowledge. If you need to suggest a page, use the list below.

Pages on the site:
- Home (/): general introduction
- People (/people): list of advocates
- Capabilities (/capabilities): practice areas
- Insights (/insights): articles
- Join Us (/join-us): information about the firm and lead advocate
- Contact (/contact): contact form
- Case Studies (/case-studies): client success stories
- Capability detail (/capabilities/:id): specific practice area

When a user asks to go to a page (e.g., "take me to contact", "show me people"), respond with a JSON object: { "action": "navigate", "path": "/contact" }.
If the user asks a question, respond with a JSON object: { "action": "answer", "answer": "your text answer" }.
If the question is about a specific topic, try to include a relevant page suggestion in your answer (as plain text).
`;

    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: message }
      ],
      temperature: 0.5,
      response_format: { type: 'json_object' },
    });

    const responseText = completion.choices[0].message.content;
    if (!responseText) throw new Error('No response');

    const parsed = JSON.parse(responseText);
    res.json(parsed);
  } catch (error) {
    console.error('Assistant error:', error);
    res.status(500).json({ error: 'Assistant processing failed' });
  }
});

// ========== Global error handler ==========
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('🔥 Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ========== Export serverless handler ==========
export default serverless(app);

// ========== Start local server for development ==========
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`✅ Local backend running on http://localhost:${PORT}`);
    console.log(`🖼️  Uploads Directory: ${uploadsDir}`);
  });
}