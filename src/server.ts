import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import authRoutes from './src/routes/auth.js';
import staffRoutes from './src/routes/staff.js';
import aiRoutes from './src/routes/ai.js';

dotenv.config();
const app = express();

app.use(cors({
  origin: [process.env.ADMIN_FRONTEND_URL || 'http://localhost:5173', 'https://adansonia-admin.vercel.app'],
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));

// Plug in the modular routes
app.use('/api/auth', authRoutes);
app.use('/api/staff', staffRoutes);
app.use('/api/ai', aiRoutes);

app.get('/health', (req, res) => res.status(200).send('✅ Adansonia API Modular System Online'));

export default app;