import mongoose from 'mongoose';

const capabilitySchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  icon: String,
  priority: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now }
});

export default mongoose.model('Capability', capabilitySchema);