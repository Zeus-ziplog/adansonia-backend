import mongoose from 'mongoose';

const testimonialSchema = new mongoose.Schema({
  name: { type: String, required: true },
  role: String,
  quote: { type: String, required: true },
  avatar: String,
  created_at: { type: Date, default: Date.now }
});

export default mongoose.model('Testimonial', testimonialSchema);