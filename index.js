// server.js - Node.js Express backend for Taqwa Home Delivery

require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors()); // Allow cross-origin requests from your frontend
app.use(express.json()); // Enable JSON body parsing

// --- Temporary In-Memory Database (Replace with a real database in production) ---
// Hardcode an admin user for testing purposes.
let users = [
    { name: 'Admin User', email: 'admin@taqwa.com', password: 'admin123', phone: '1234567890', isVerified: true, role: 'admin' },
];
let verificationCodes = {};
let orders = []; // Simple array to store orders
let notifications = []; // Simple array to store notifications

// --- Email Transporter Setup using Nodemailer ---
// You will need to set up a "App Password" for your Gmail account.
// See instructions at the bottom on how to do this.
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// --- JWT Middleware to authenticate and authorize users ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ message: "Authentication token missing." });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err);
            return res.status(403).json({ message: "Invalid or expired token." });
        }
        req.user = user;
        next();
    });
}

// Middleware to check for admin role
function checkAdminRole(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: "Access denied. Admins only." });
    }
    next();
}

// --- API Endpoints ---

// Registration endpoint
app.post('/api/register', async (req, res) => {
    const { name, email, password, phone } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    if (users.find(user => user.email === email)) {
        return res.status(409).json({ message: 'User with this email already exists.' });
    }

    // Generate a 6-digit verification code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const newUser = { name, email, password, phone, isVerified: false, role: 'user' };

    // Store the new user and verification code (in a real app, use a database)
    users.push(newUser);
    verificationCodes[email] = { code, expires: Date.now() + 10 * 60 * 1000 }; // 10 minutes expiry

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Taqwa Home Delivery - Email Verification',
        html: `
            <h1>Welcome to Taqwa Home Delivery!</h1>
            <p>Thank you for registering. Please use the following code to verify your account:</p>
            <h2><b>${code}</b></h2>
            <p>This code is valid for 10 minutes.</p>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Registration successful! Verification code sent to your email.' });
    } catch (error) {
        console.error('Error sending email:', error);
        // Remove the user from the temporary database if email sending fails
        users = users.filter(user => user.email !== email);
        res.status(500).json({ message: 'Failed to send verification email.' });
    }
});

// Verification endpoint
app.post('/api/verify-email', (req, res) => {
    const { email, code } = req.body;

    const user = users.find(user => user.email === email);
    const storedCode = verificationCodes[email];

    if (!user || !storedCode) {
        return res.status(400).json({ message: 'Invalid email or no verification code found.' });
    }

    if (storedCode.expires < Date.now()) {
        delete verificationCodes[email]; // Clean up expired code
        return res.status(400).json({ message: 'Verification code has expired. Please resend.' });
    }

    if (storedCode.code === code) {
        user.isVerified = true;
        delete verificationCodes[email]; // Verification successful, delete the code
        return res.status(200).json({ message: 'Email verified successfully!' });
    } else {
        return res.status(400).json({ message: 'Invalid verification code.' });
    }
});

// Resend verification code endpoint
app.post('/api/resend-code', async (req, res) => {
    const { email } = req.body;
    const user = users.find(u => u.email === email);

    if (!user) {
        return res.status(404).json({ message: 'User not found.' });
    }

    const newCode = Math.floor(100000 + Math.random() * 900000).toString();
    verificationCodes[email] = { code: newCode, expires: Date.now() + 10 * 60 * 1000 };

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Taqwa Home Delivery - Resend Verification Code',
        html: `<p>Your new verification code is: <b>${newCode}</b></p>`
    };

    try {
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'New verification code sent to your email.' });
    } catch (error) {
        console.error('Error resending email:', error);
        res.status(500).json({ message: 'Failed to resend verification code.' });
    }
});


// Login endpoint
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    const user = users.find(user => user.email === email && user.password === password); // WARNING: Use password hashing (e.g., bcrypt) in a real application.

    if (!user) {
        return res.status(401).json({ message: 'Invalid email or password.' });
    }

    if (!user.isVerified) {
        return res.status(403).json({ message: 'Please verify your email before logging in.' });
    }

    // Create a JWT token
    const token = jwt.sign({ email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ message: 'Login successful!', token, user: { name: user.name, email: user.email, role: user.role } });
});

// Admin-only: Get all users
app.get('/api/admin/users', authenticateToken, checkAdminRole, (req, res) => {
    // Send back a sanitized list of users (without passwords)
    const sanitizedUsers = users.map(user => ({
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified
    }));
    res.status(200).json({ users: sanitizedUsers });
});

// Admin-only: Get all orders
app.get('/api/admin/orders', authenticateToken, checkAdminRole, (req, res) => {
    res.status(200).json({ orders });
});

// Admin-only: Send a notification to all users
app.post('/api/admin/notifications', authenticateToken, checkAdminRole, (req, res) => {
    const { title, message } = req.body;
    if (!title || !message) {
        return res.status(400).json({ message: 'Notification title and message are required.' });
    }

    const newNotification = {
        id: notifications.length + 1,
        title,
        message,
        timestamp: new Date()
    };
    notifications.push(newNotification);

    res.status(200).json({ message: 'Notification sent successfully!', notification: newNotification });
});

// Start the server
app.listen(port, () => {
    console.log(`Backend server listening on port ${port}`);
});
