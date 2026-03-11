import mongoose from 'mongoose';

const staffSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: String,
  role: String,
  expertise: [String],
  priority: { type: Number, default: 0 },
  image_url: String,
  bio: String,
  created_at: { type: Date, default: Date.now }
});

export default mongoose.model('Staff', staffSchema);