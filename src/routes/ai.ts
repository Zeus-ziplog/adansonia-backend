import { Router } from 'express';

const router = Router();

router.post('/assistant', async (req, res) => {
  try {
    const { message } = req.body;
    const { default: Groq } = await import('groq-sdk');
    const groq = new Groq({ apiKey: process.env.GROQ_API_KEY! });

    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: 'You are a legal assistant for Adansonia Law Firm. Respond in JSON.' },
        { role: 'user', content: message },
      ],
      response_format: { type: 'json_object' },
    });
    
    res.json(JSON.parse(completion.choices[0].message.content || '{}'));
  } catch (error) {
    res.status(500).json({ error: 'AI processing failed' });
  }
});

export default router;