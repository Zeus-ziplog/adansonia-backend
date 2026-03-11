import mongoose from 'mongoose';

const caseStudySchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  practiceArea: String,
  image_url: String,
  client: String,
  outcome: String,
  created_at: { type: Date, default: Date.now }
});

export default mongoose.model('CaseStudy', caseStudySchema);