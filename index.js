require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ DB connection failed:', err));

// User model
const UserSchema = new mongoose.Schema({
    name: String,
    email: String,
    phone: String,
    password: String,
    isVerified: { type: Boolean, default: false },
    role: { type: String, default: 'user' }
});
const User = mongoose.model('User', UserSchema);

// Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Registration endpoint
app.post('/api/register', async (req, res) => {
    const { name, email, password, phone } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: 'User with this email already exists.' });
        }

        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const newUser = new User({ name, email, phone, password, isVerified: false });
        await newUser.save();

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Taqwa Home Delivery - Email Verification',
            html: `<h1>Welcome!</h1><p>Your code is:</p><h2>${code}</h2>`
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Registration successful! Verification code sent to your email.' });

    } catch (err) {
        console.error('❌ Error in /api/register:', err);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
