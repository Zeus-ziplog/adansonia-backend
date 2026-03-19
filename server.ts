import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import Groq from 'groq-sdk';
import dotenv from 'dotenv';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import serverless from 'serverless-http';
import { PrismaClient } from '@prisma/client';
import { v2 as cloudinary } from 'cloudinary';

dotenv.config();

// ========== 1. CLOUDINARY CONFIG ==========
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ========== 2. PRISMA SERVERLESS OPTIMIZATION ==========
const globalForPrisma = global as unknown as { prisma: PrismaClient };
export const prisma = globalForPrisma.prisma || new PrismaClient();
if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || 'adansonia-secret-key-2024';
const ADMIN_FRONTEND_URL = process.env.ADMIN_FRONTEND_URL || 'http://localhost:5173';
const isVercel = process.env.VERCEL === '1';

// ========== 3. MIDDLEWARE ==========
app.use(cors({
  origin: ADMIN_FRONTEND_URL,
  credentials: true,
}));
app.use(express.json({ limit: '50mb' }));

// Request logger (optional, but helpful for debugging)
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Session (needed for Passport)
app.use(session({
  secret: process.env.SESSION_SECRET || 'adansonia-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    sameSite: 'none',
    maxAge: 24 * 60 * 60 * 1000,
  },
}));

app.use(passport.initialize());
app.use(passport.session());

// ========== 4. CLOUDINARY UPLOAD HELPER ==========
const uploadToCloudinary = async (base64String: string, folder: string): Promise<string | null> => {
  try {
    const uploadResponse = await cloudinary.uploader.upload(base64String, {
      folder: `adansonia/${folder}`,
    });
    return uploadResponse.secure_url;
  } catch (error) {
    console.error('Cloudinary upload error:', error);
    return null;
  }
};

// ========== 5. AUTH MIDDLEWARE ==========
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

// ========== 6. PASSPORT GOOGLE STRATEGY ==========
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:5000/api/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value;
    if (!email) return done(null, false);

    let admin = await prisma.admin.findUnique({ where: { email } });
    if (!admin) {
      // Optional: auto‑create admin? For now, reject.
      return done(null, false);
    }

    // Update avatar if needed
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

passport.serializeUser((user: any, done) => done(null, user.id));
passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await prisma.admin.findUnique({ where: { id } });
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ========== 7. DIAGNOSTIC ROUTES ==========
app.get('/health', (req, res) => res.send('OK'));
app.get('/ping', (req, res) => res.send('pong'));
app.get('/test-db', async (req, res) => {
  try {
    const result = await prisma.$queryRaw`SELECT 1 as test`;
    res.json({ success: true, result });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========== 8. AUTH ROUTES ==========
app.get('/', (req, res) => res.send('✅ Adansonia backend is live!'));

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

app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: `${ADMIN_FRONTEND_URL}/login`, session: false }),
  (req, res) => {
    try {
      const user = req.user as any;
      const token = jwt.sign(
        { id: user.id, email: user.email, avatar: user.avatar },
        SECRET_KEY,
        { expiresIn: '7d' }
      );
      res.redirect(`${ADMIN_FRONTEND_URL}/login?token=${token}&email=${encodeURIComponent(user.email)}&avatar=${encodeURIComponent(user.avatar || '')}`);
    } catch (err) {
      res.redirect(`${ADMIN_FRONTEND_URL}/login?error=auth_failed`);
    }
  }
);

// ========== 9. ADMIN MANAGEMENT ==========
app.post('/api/admin/register', verifyToken, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const existing = await prisma.admin.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ error: 'Admin already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = await prisma.admin.create({
      data: { email, password: hashedPassword, created_at: new Date(), avatar: null },
    });
    res.json({ success: true, email: newAdmin.email });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create admin' });
  }
});

app.get('/api/admin/admins', verifyToken, async (req, res) => {
  try {
    const admins = await prisma.admin.findMany({ select: { id: true, email: true, avatar: true, created_at: true, googleId: true } });
    res.json(admins);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch admins' });
  }
});

app.delete('/api/admin/admins/:id', verifyToken, async (req, res) => {
  try {
    await prisma.admin.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete admin' });
  }
});

// ========== 10. STAFF ROUTES (with Cloudinary) ==========
app.get('/api/staff', async (req, res) => {
  const staff = await prisma.staff.findMany({ orderBy: { priority: 'asc' } });
  res.json(staff);
});

app.get('/api/staff/:id', async (req, res) => {
  const member = await prisma.staff.findUnique({ where: { id: req.params.id } });
  if (!member) return res.status(404).json({ error: 'Not found' });
  res.json(member);
});

app.get('/api/admin/staff', verifyToken, async (req, res) => {
  const staff = await prisma.staff.findMany({ orderBy: { priority: 'asc' } });
  res.json(staff);
});

app.post('/api/admin/staff', verifyToken, async (req, res) => {
  try {
    const { name, email, image_base64, bio, priority, role, expertise } = req.body;
    let imageUrl = '';
    if (image_base64) {
      imageUrl = (await uploadToCloudinary(image_base64, 'staff')) || '';
    }
    const newStaff = await prisma.staff.create({
      data: {
        name,
        email,
        role,
        expertise: expertise || [],
        priority: priority || 0,
        image_url: imageUrl,
        bio,
      },
    });
    res.json(newStaff);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create staff' });
  }
});

app.put('/api/admin/staff/:id', verifyToken, async (req, res) => {
  try {
    const { image_base64, ...rest } = req.body;
    let imageUrl;
    if (image_base64) {
      imageUrl = (await uploadToCloudinary(image_base64, 'staff')) || undefined;
    }
    const updateData: any = { ...rest };
    if (imageUrl) updateData.image_url = imageUrl;

    const updated = await prisma.staff.update({
      where: { id: req.params.id },
      data: updateData,
    });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update staff' });
  }
});

app.delete('/api/admin/staff/:id', verifyToken, async (req, res) => {
  await prisma.staff.delete({ where: { id: req.params.id } });
  res.json({ success: true });
});

// ========== 11. TESTIMONIALS ROUTES ==========
app.get('/api/testimonials', async (req, res) => {
  res.json(await prisma.testimonial.findMany());
});

app.get('/api/testimonials/:id', async (req, res) => {
  const item = await prisma.testimonial.findUnique({ where: { id: req.params.id } });
  if (!item) return res.status(404).json({ error: 'Not found' });
  res.json(item);
});

app.get('/api/admin/testimonials', verifyToken, async (req, res) => {
  res.json(await prisma.testimonial.findMany());
});

app.post('/api/admin/testimonials', verifyToken, async (req, res) => {
  try {
    const { name, role, quote, avatar } = req.body;
    if (!name || !quote) return res.status(400).json({ error: 'Name and quote required' });
    const newItem = await prisma.testimonial.create({ data: { name, role, quote, avatar } });
    res.json(newItem);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create testimonial' });
  }
});

app.put('/api/admin/testimonials/:id', verifyToken, async (req, res) => {
  try {
    const updated = await prisma.testimonial.update({
      where: { id: req.params.id },
      data: req.body,
    });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update testimonial' });
  }
});

app.delete('/api/admin/testimonials/:id', verifyToken, async (req, res) => {
  await prisma.testimonial.delete({ where: { id: req.params.id } });
  res.json({ success: true });
});

// ========== 12. INSIGHTS ROUTES (with Cloudinary) ==========
app.get('/api/insights', async (req, res) => {
  const insights = await prisma.insight.findMany({ orderBy: { published_date: 'desc' } });
  res.json(insights);
});

app.get('/api/insights/:id', async (req, res) => {
  const insight = await prisma.insight.findUnique({ where: { id: req.params.id } });
  if (!insight) return res.status(404).json({ error: 'Not found' });
  res.json(insight);
});

app.get('/api/admin/insights', verifyToken, async (req, res) => {
  const insights = await prisma.insight.findMany({ orderBy: { published_date: 'desc' } });
  res.json(insights);
});

app.post('/api/admin/insights', verifyToken, async (req, res) => {
  try {
    const { title, content, published_date, published, category, tags, image_base64 } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'Title and content required' });

    let imageUrl = '';
    if (image_base64) {
      imageUrl = (await uploadToCloudinary(image_base64, 'insights')) || '';
    }

    const newInsight = await prisma.insight.create({
      data: {
        title,
        content,
        published_date: published_date ? new Date(published_date) : new Date(),
        published: published !== undefined ? published : true,
        category: category || '',
        tags: tags ? (Array.isArray(tags) ? tags : tags.split(',').map((t: string) => t.trim())) : [],
        image_url: imageUrl,
      },
    });
    res.json(newInsight);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create insight' });
  }
});

app.put('/api/admin/insights/:id', verifyToken, async (req, res) => {
  try {
    const { image_base64, ...rest } = req.body;
    let imageUrl;
    if (image_base64) {
      imageUrl = (await uploadToCloudinary(image_base64, 'insights')) || undefined;
    }
    const updateData: any = { ...rest };
    if (imageUrl) updateData.image_url = imageUrl;

    const updated = await prisma.insight.update({
      where: { id: req.params.id },
      data: updateData,
    });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update insight' });
  }
});

app.delete('/api/admin/insights/:id', verifyToken, async (req, res) => {
  await prisma.insight.delete({ where: { id: req.params.id } });
  res.json({ success: true });
});

// ========== 13. CAPABILITIES ROUTES ==========
app.get('/api/capabilities', async (req, res) => {
  const caps = await prisma.capability.findMany({ orderBy: { priority: 'asc' } });
  res.json(caps);
});

app.get('/api/capabilities/:id', async (req, res) => {
  const item = await prisma.capability.findUnique({ where: { id: req.params.id } });
  if (!item) return res.status(404).json({ error: 'Not found' });
  res.json(item);
});

app.get('/api/admin/capabilities', verifyToken, async (req, res) => {
  const caps = await prisma.capability.findMany({ orderBy: { priority: 'asc' } });
  res.json(caps);
});

app.post('/api/admin/capabilities', verifyToken, async (req, res) => {
  try {
    const { title, description, icon, priority } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    const newItem = await prisma.capability.create({
      data: { title, description, icon, priority: priority || 0 },
    });
    res.json(newItem);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create capability' });
  }
});

app.put('/api/admin/capabilities/:id', verifyToken, async (req, res) => {
  try {
    const updated = await prisma.capability.update({
      where: { id: req.params.id },
      data: req.body,
    });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update capability' });
  }
});

app.delete('/api/admin/capabilities/:id', verifyToken, async (req, res) => {
  await prisma.capability.delete({ where: { id: req.params.id } });
  res.json({ success: true });
});

// ========== 14. CASE STUDIES ROUTES (with Cloudinary) ==========
app.get('/api/case-studies', async (req, res) => {
  res.json(await prisma.caseStudy.findMany());
});

app.get('/api/case-studies/:id', async (req, res) => {
  const item = await prisma.caseStudy.findUnique({ where: { id: req.params.id } });
  if (!item) return res.status(404).json({ error: 'Not found' });
  res.json(item);
});

app.get('/api/admin/case-studies', verifyToken, async (req, res) => {
  res.json(await prisma.caseStudy.findMany());
});

app.post('/api/admin/case-studies', verifyToken, async (req, res) => {
  try {
    const { title, description, practiceArea, image_base64, client, outcome } = req.body;
    if (!title || !description) return res.status(400).json({ error: 'Title and description required' });

    let imageUrl = '';
    if (image_base64) {
      imageUrl = (await uploadToCloudinary(image_base64, 'case-studies')) || '';
    }

    const newItem = await prisma.caseStudy.create({
      data: {
        title,
        description,
        practiceArea,
        image_url: imageUrl,
        client,
        outcome,
      },
    });
    res.json(newItem);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create case study' });
  }
});

app.put('/api/admin/case-studies/:id', verifyToken, async (req, res) => {
  try {
    const { image_base64, ...rest } = req.body;
    let imageUrl;
    if (image_base64) {
      imageUrl = (await uploadToCloudinary(image_base64, 'case-studies')) || undefined;
    }
    const updateData: any = { ...rest };
    if (imageUrl) updateData.image_url = imageUrl;

    const updated = await prisma.caseStudy.update({
      where: { id: req.params.id },
      data: updateData,
    });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update case study' });
  }
});

app.delete('/api/admin/case-studies/:id', verifyToken, async (req, res) => {
  await prisma.caseStudy.delete({ where: { id: req.params.id } });
  res.json({ success: true });
});

// ========== 15. CONTACT MESSAGES ROUTES ==========
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    if (!name || !email || !message) return res.status(400).json({ error: 'Missing fields' });
    const newMessage = await prisma.contactMessage.create({ data: { name, email, message } });
    res.json({ success: true, id: newMessage.id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.get('/api/admin/contact', verifyToken, async (req, res) => {
  const messages = await prisma.contactMessage.findMany({ orderBy: { created_at: 'desc' } });
  res.json(messages);
});

app.delete('/api/admin/contact/:id', verifyToken, async (req, res) => {
  await prisma.contactMessage.delete({ where: { id: req.params.id } });
  res.json({ success: true });
});

// ========== 16. AI ASSISTANT ==========
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY! });
app.post('/api/assistant', async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });

    const systemPrompt = `You are a helpful assistant for the law firm "Adansonia Kiamba Mbithi & Co. Advocates". 
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
If the question is about a specific topic, try to include a relevant page suggestion in your answer (as plain text).`;

    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: message },
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

// ========== 17. GLOBAL ERROR HANDLER ==========
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('🔥 Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ========== 18. EXPORT SERVERLESS HANDLER ==========
export default serverless(app);

// ========== 19. LOCAL DEVELOPMENT ==========
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`✅ Local backend running on http://localhost:${PORT}`);
  });
}