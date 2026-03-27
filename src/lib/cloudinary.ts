export const uploadToCloudinary = async (base64String: string, folder: string): Promise<string | null> => {
  try {
    const { v2: cloudinary } = await import('cloudinary');
    cloudinary.config({
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
      api_key: process.env.CLOUDINARY_API_KEY,
      api_secret: process.env.CLOUDINARY_API_SECRET,
    });
    const uploadResponse = await cloudinary.uploader.upload(base64String, {
      folder: `adansonia/${folder}`,
    });
    return uploadResponse.secure_url;
  } catch (error) {
    console.error('Cloudinary error:', error);
    return null;
  }
};