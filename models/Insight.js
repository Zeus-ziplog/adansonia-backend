import mongoose from 'mongoose';

const insightSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  published_date: String,
  published: { type: Boolean, default: true },
  category: String,
  tags: [String],
  image_url: String,
  created_at: { type: Date, default: Date.now }
});

export default mongoose.model('Insight', insightSchema);