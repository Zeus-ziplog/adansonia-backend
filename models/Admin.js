import mongoose from 'mongoose';

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: String,
  googleId: String,
  avatar: String,
  created_at: { type: Date, default: Date.now }
});

export default mongoose.model('Admin', adminSchema);