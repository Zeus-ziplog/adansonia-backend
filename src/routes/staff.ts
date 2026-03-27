import { Router } from 'express';
import { prisma } from '../lib/prisma.js';
import { uploadToCloudinary } from '../lib/cloudinary.js';

const router = Router();

router.get('/', async (req, res) => {
  const staff = await prisma.staff.findMany({ orderBy: { priority: 'asc' } });
  res.json(staff);
});

router.post('/', async (req, res) => {
  try {
    const { image_base64, ...data } = req.body;
    let image_url = '';
    if (image_base64) {
      image_url = (await uploadToCloudinary(image_base64, 'staff')) || '';
    }
    const newStaff = await prisma.staff.create({ data: { ...data, image_url } });
    res.json(newStaff);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create staff' });
  }
});

export default router;