import { Router } from 'express';
import Groq from 'groq-sdk';

const router = Router();
// Initialize once at the top to prevent lag
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

router.post('/assistant', async (req, res) => {
  try {
    const { message } = req.body;

    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { 
          role: 'system', 
          content: 'You are a legal assistant for Adansonia-Kiamba-Mbithi Advocates. Respond in valid JSON.' 
        },
        { role: 'user', content: message },
      ],
      response_format: { type: 'json_object' },
    });
    
    const content = completion.choices[0].message.content || '{}';
    res.json(JSON.parse(content));
  } catch (error) {
    console.error("Groq Assistant Error:", error);
    res.status(500).json({ error: 'Legal AI processing failed' });
  }
});

export default router;