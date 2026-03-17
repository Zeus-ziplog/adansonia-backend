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
import mongoose from 'mongoose';
import serverless from 'serverless-http';

// Import Mongoose models
import Admin from './models/Admin.js';
import Staff from './models/Staff.js';
import Testimonial from './models/Testimonial.js';
import Insight from './models/Insight.js';
import Capability from './models/Capability.js';
import CaseStudy from './models/CaseStudy.js';
import ContactMessage from './models/ContactMessage.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || 'adansonia-secret-key-2024';
const ADMIN_FRONTEND_URL = process.env.ADMIN_FRONTEND_URL || 'http://localhost:5173';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ========== MongoDB Connection with Timeout ==========
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI environment variable is not defined');
  // Don't exit – we'll handle it in requests
} else {
  // Set connection timeout to 10 seconds
  mongoose.connect(MONGODB_URI, {
    serverSelectionTimeoutMS: 10000, // Timeout after 10s
    socketTimeoutMS: 45000, // Close sockets after 45s of inactivity
  })
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => {
      console.error('❌ MongoDB connection error:', err.message);
      // Don't exit – let the function start, but requests will fail gracefully
    });
}

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
  // Check if MongoDB is connected
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'Database not connected' });
  }
  res.send('✅ Adansonia backend is live on Vercel!');
});

// ========== Uploads directory – handle gracefully ==========
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

// ========== Middleware to check DB connection for API routes ==========
const checkDbConnection = (req: Request, res: Response, next: NextFunction) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'Database not connected' });
  }
  next();
};

// Apply DB check to all API routes (except maybe auth routes that don't need DB? but most do)
app.use('/api', checkDbConnection);

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

      let admin = await Admin.findOne({ email });
      if (!admin) {
        console.log('❓ No admin found for email:', email);
        return done(null, false, { message: 'Admin not found' });
      }

      if (!admin.avatar || admin.avatar !== avatar) {
        admin.avatar = avatar;
        if (!admin.googleId) admin.googleId = profile.id;
        await admin.save();
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
    const user = await Admin.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ========== AUTH ROUTES ==========
app.post('/api/auth/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, rememberMe } = req.body;

    const adminCount = await Admin.countDocuments();
    if (adminCount === 0 && email === 'admin@adansonia.com' && password === 'password123') {
      const expiresIn = rememberMe ? '30d' : '7d';
      const token = jwt.sign({ id: 'initial', email }, SECRET_KEY, { expiresIn });
      res.json({ token, email });
      return;
    }

    const admin = await Admin.findOne({ email });
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

    const existing = await Admin.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: 'Admin already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new Admin({
      email,
      password: hashedPassword,
      created_at: new Date(),
      avatar: null
    });
    await newAdmin.save();

    res.json({ success: true, email: newAdmin.email });
  } catch (err) {
    console.error('Admin registration error:', err);
    res.status(500).json({ error: 'Failed to create admin' });
  }
});

app.get('/api/admin/admins', verifyToken, async (req: Request, res: Response) => {
  try {
    const admins = await Admin.find().select('-password');
    res.json(admins);
  } catch (err) {
    console.error('Fetch admins error:', err);
    res.status(500).json({ error: 'Failed to fetch admins' });
  }
});

app.delete('/api/admin/admins/:id', verifyToken, async (req: Request, res: Response) => {
  try {
    const result = await Admin.findByIdAndDelete(req.params.id);
    if (!result) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete admin error:', err);
    res.status(500).json({ error: 'Failed to delete admin' });
  }
});

// ========== STAFF ROUTES ==========
app.get('/api/staff', async (req, res) => {
  try {
    const staff = await Staff.find().sort({ priority: 1 });
    res.json(staff);
  } catch (err) {
    console.error('Fetch staff error:', err);
    res.status(500).json({ error: 'Failed to fetch staff' });
  }
});

app.get('/api/staff/:id', async (req, res) => {
  try {
    const member = await Staff.findById(req.params.id);
    if (!member) return res.status(404).json({ error: 'Not found' });
    res.json(member);
  } catch (err) {
    console.error('Fetch staff by id error:', err);
    res.status(500).json({ error: 'Invalid ID or server error' });
  }
});

app.get('/api/admin/staff', verifyToken, async (req, res) => {
  try {
    const staff = await Staff.find().sort({ priority: 1 });
    res.json(staff);
  } catch (err) {
    console.error('Fetch admin staff error:', err);
    res.status(500).json({ error: 'Failed to fetch staff' });
  }
});

// Disable file upload endpoints on Vercel
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

    const newStaff = new Staff({
      name,
      email,
      role,
      expertise: expertise || [],
      priority: priority || 0,
      image_url: imageUrl,
      bio
    });
    await newStaff.save();
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

    const updateData = { ...rest };
    if (imageUrl) updateData.image_url = imageUrl;

    const updated = await Staff.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json(updated);
  } catch (err) {
    console.error('Update staff error:', err);
    res.status(500).json({ error: 'Failed to update staff' });
  }
});

app.delete('/api/admin/staff/:id', verifyToken, async (req, res) => {
  try {
    const deleted = await Staff.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete staff error:', err);
    res.status(500).json({ error: 'Failed to delete staff' });
  }
});

// ========== TESTIMONIALS ROUTES ==========
app.get('/api/testimonials', async (req, res) => {
  try {
    const testimonials = await Testimonial.find();
    res.json(testimonials);
  } catch (err) {
    console.error('Fetch testimonials error:', err);
    res.status(500).json({ error: 'Failed to fetch testimonials' });
  }
});

app.get('/api/testimonials/:id', async (req, res) => {
  try {
    const item = await Testimonial.findById(req.params.id);
    if (!item) return res.status(404).json({ error: 'Not found' });
    res.json(item);
  } catch (err) {
    console.error('Fetch testimonial by id error:', err);
    res.status(500).json({ error: 'Invalid ID' });
  }
});

app.get('/api/admin/testimonials', verifyToken, async (req, res) => {
  try {
    const testimonials = await Testimonial.find();
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
    const newItem = new Testimonial({ name, role, quote, avatar });
    await newItem.save();
    res.json(newItem);
  } catch (err) {
    console.error('Create testimonial error:', err);
    res.status(500).json({ error: 'Failed to create testimonial' });
  }
});

app.put('/api/admin/testimonials/:id', verifyToken, async (req, res) => {
  try {
    const updated = await Testimonial.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json(updated);
  } catch (err) {
    console.error('Update testimonial error:', err);
    res.status(500).json({ error: 'Failed to update testimonial' });
  }
});

app.delete('/api/admin/testimonials/:id', verifyToken, async (req, res) => {
  try {
    const deleted = await Testimonial.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete testimonial error:', err);
    res.status(500).json({ error: 'Failed to delete testimonial' });
  }
});

// ========== INSIGHTS ROUTES ==========
app.get('/api/insights', async (req, res) => {
  try {
    const insights = await Insight.find().sort({ published_date: -1 });
    res.json(insights);
  } catch (err) {
    console.error('Fetch insights error:', err);
    res.status(500).json({ error: 'Failed to fetch insights' });
  }
});

app.get('/api/insights/:id', async (req, res) => {
  try {
    const insight = await Insight.findById(req.params.id);
    if (!insight) return res.status(404).json({ error: 'Not found' });
    res.json(insight);
  } catch (err) {
    console.error('Fetch insight by id error:', err);
    res.status(500).json({ error: 'Invalid ID' });
  }
});

app.get('/api/admin/insights', verifyToken, async (req, res) => {
  try {
    const insights = await Insight.find().sort({ published_date: -1 });
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

    const newInsight = new Insight({
      title,
      content,
      published_date: published_date || new Date().toISOString().split('T')[0],
      published: published !== undefined ? published : true,
      category: category || '',
      tags: tags ? (Array.isArray(tags) ? tags : tags.split(',').map((t: string) => t.trim())) : [],
      image_url: imageUrl,
    });
    await newInsight.save();
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
    const updateData = { ...rest };
    if (imageUrl) updateData.image_url = imageUrl;

    const updated = await Insight.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json(updated);
  } catch (err) {
    console.error('Update insight error:', err);
    res.status(500).json({ error: 'Failed to update insight' });
  }
});

app.delete('/api/admin/insights/:id', verifyToken, async (req, res) => {
  try {
    const deleted = await Insight.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete insight error:', err);
    res.status(500).json({ error: 'Failed to delete insight' });
  }
});

// ========== CAPABILITIES ROUTES ==========
app.get('/api/capabilities', async (req, res) => {
  try {
    const caps = await Capability.find().sort({ priority: 1 });
    res.json(caps);
  } catch (err) {
    console.error('Fetch capabilities error:', err);
    res.status(500).json({ error: 'Failed to fetch capabilities' });
  }
});

app.get('/api/capabilities/:id', async (req, res) => {
  try {
    const item = await Capability.findById(req.params.id);
    if (!item) return res.status(404).json({ error: 'Not found' });
    res.json(item);
  } catch (err) {
    console.error('Fetch capability by id error:', err);
    res.status(500).json({ error: 'Invalid ID' });
  }
});

app.get('/api/admin/capabilities', verifyToken, async (req, res) => {
  try {
    const caps = await Capability.find().sort({ priority: 1 });
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
    const newItem = new Capability({ title, description, icon, priority });
    await newItem.save();
    res.json(newItem);
  } catch (err) {
    console.error('Create capability error:', err);
    res.status(500).json({ error: 'Failed to create capability' });
  }
});

app.put('/api/admin/capabilities/:id', verifyToken, async (req, res) => {
  try {
    const updated = await Capability.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json(updated);
  } catch (err) {
    console.error('Update capability error:', err);
    res.status(500).json({ error: 'Failed to update capability' });
  }
});

app.delete('/api/admin/capabilities/:id', verifyToken, async (req, res) => {
  try {
    const deleted = await Capability.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete capability error:', err);
    res.status(500).json({ error: 'Failed to delete capability' });
  }
});

// ========== CASE STUDIES ROUTES ==========
app.get('/api/case-studies', async (req, res) => {
  try {
    const studies = await CaseStudy.find();
    res.json(studies);
  } catch (err) {
    console.error('Fetch case studies error:', err);
    res.status(500).json({ error: 'Failed to fetch case studies' });
  }
});

app.get('/api/case-studies/:id', async (req, res) => {
  try {
    const item = await CaseStudy.findById(req.params.id);
    if (!item) return res.status(404).json({ error: 'Not found' });
    res.json(item);
  } catch (err) {
    console.error('Fetch case study by id error:', err);
    res.status(500).json({ error: 'Invalid ID' });
  }
});

app.get('/api/admin/case-studies', verifyToken, async (req, res) => {
  try {
    const studies = await CaseStudy.find();
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

    const newItem = new CaseStudy({
      title,
      description,
      practiceArea,
      image_url: imageUrl,
      client,
      outcome
    });
    await newItem.save();
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
    const updateData = { ...rest };
    if (imageUrl) updateData.image_url = imageUrl;

    const updated = await CaseStudy.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json(updated);
  } catch (err) {
    console.error('Update case study error:', err);
    res.status(500).json({ error: 'Failed to update case study' });
  }
});

app.delete('/api/admin/case-studies/:id', verifyToken, async (req, res) => {
  try {
    const deleted = await CaseStudy.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Not found' });
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
    const newMessage = new ContactMessage({ name, email, message });
    await newMessage.save();
    res.json({ success: true, id: newMessage.id });
  } catch (err) {
    console.error('Contact form error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.get('/api/admin/contact', verifyToken, async (req, res) => {
  try {
    const messages = await ContactMessage.find().sort({ created_at: -1 });
    res.json(messages);
  } catch (err) {
    console.error('Fetch messages error:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.delete('/api/admin/contact/:id', verifyToken, async (req, res) => {
  try {
    const deleted = await ContactMessage.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Not found' });
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