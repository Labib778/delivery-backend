// server.js

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors'); // For handling Cross-Origin Resource Sharing

const app = express();

// --- Configuration from Environment Variables ---
const PORT = process.env.PORT || 5000; // Default to 5000 if PORT isn't set
const MONGODB_URI = process.env.MONGO_URI; // Make sure this matches your .env file
const JWT_SECRET = process.env.JWT_SECRET; // Make sure this matches your .env file
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// --- Middleware ---
app.use(cors()); // Enable CORS for all origins (for development)
app.use(express.json()); // Body parser for JSON data

// --- Database Connection ---
const connectDB = async () => {
    try {
        if (!MONGODB_URI) {
            throw new Error("MONGO_URI is not defined in .env file.");
        }
        await mongoose.connect(MONGODB_URI);
        console.log('MongoDB Connected...');
        await createInitialAdminUser(); // Create admin after successful DB connection
    } catch (err) {
        console.error('MongoDB connection error:', err.message);
        process.exit(1); // Exit process with failure
    }
};

// --- Initial Admin User Creation ---
const createInitialAdminUser = async () => {
    try {
        if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
            console.warn("Admin email or password not set in .env. Skipping initial admin creation.");
            return;
        }

        let adminUser = await User.findOne({ email: ADMIN_EMAIL });
        if (!adminUser) {
            console.log("No admin user found. Creating initial admin user...");
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, salt);

            adminUser = new User({
                name: 'Admin User',
                email: ADMIN_EMAIL,
                phone: '01234567890', // A dummy phone number for admin
                password: hashedPassword,
                role: 'admin',
                isVerified: true // Admin is automatically verified
            });
            await adminUser.save();
            console.log('Initial admin user created successfully!');
        } else {
            // Optional: If you want to update admin password if it's "0"
            // if (ADMIN_PASSWORD === "0" && bcrypt.compareSync("0", adminUser.password)) {
            //     const salt = await bcrypt.genSalt(10);
            //     adminUser.password = await bcrypt.hash("YOUR_NEW_ADMIN_PASSWORD_HERE", salt);
            //     await adminUser.save();
            //     console.log("Admin password updated to a stronger one. Please change 'ADMIN_PASSWORD=0' in your .env file!");
            // }
        }
    } catch (err) {
        console.error('Error creating initial admin user:', err.message);
    }
};

// Initialize DB connection
connectDB();

// --- Mongoose Schemas and Models ---

// User schema and model
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true, unique: true }, // Added phone
    password: { type: String, required: true }, // Renamed from passwordHash for clarity
    address: { type: String, default: '' }, // For profile
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    isVerified: { type: Boolean, default: false }, // For phone verification
    verificationCode: { type: String }, // For OTP
    verificationCodeExpires: { type: Date } // Expiry for OTP
}, { timestamps: true });
const User = mongoose.model('User', UserSchema);

// Order schema and model
const OrderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userName: { type: String, required: true }, // Denormalized for easier admin view
    product: { type: String, required: true },
    qty: { type: String, required: true }, // qty can store text like "H", "Sg", "10", etc.
    address: { type: String, required: true },
    phone: { type: String, required: true },
    message: { type: String, default: '' }, // Added for custom messages
    status: {
        type: String,
        enum: ['Pending', 'Confirmed', 'Delivered', 'Cancelled'],
        default: 'Pending'
    }
}, { timestamps: true }); // Use timestamps for createdAt and updatedAt
const Order = mongoose.model('Order', OrderSchema);

// --- Middleware for Authentication and Authorization ---

// JWT Authentication Middleware
const auth = (req, res, next) => {
    // Get token from header
    const token = req.header('Authorization');

    // Check if not token
    if (!token) {
        return res.status(401).json({ error: 'No token, authorization denied' });
    }

    try {
        // Token format is "Bearer <token>", so we split it
        const tokenString = token.split(' ')[1];
        if (!tokenString) {
            return res.status(401).json({ error: 'Token format invalid' });
        }

        if (!JWT_SECRET) {
            throw new Error("JWT_SECRET is not defined in .env file.");
        }

        const decoded = jwt.verify(tokenString, JWT_SECRET);

        // Attach user from token payload to request object
        req.user = decoded.user; // decoded.user will contain { id: user._id, role: user.role }
        next();
    } catch (err) {
        // Log the actual error for debugging
        console.error("JWT Verification Error:", err.message);
        res.status(401).json({ error: 'Token is not valid' });
    }
};

// Admin Authorization Middleware
const admin = (req, res, next) => {
    // Check if user exists and has admin role (req.user is set by auth middleware)
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access denied' });
    }
    next();
};

// --- Utility Functions (e.g., for OTP) ---
// In a real application, you would integrate with an SMS gateway (e.g., Twilio)
// or email service (e.g., SendGrid) here to send the actual OTP.
const generateOTP = () => {
    return Math.floor(1000 + Math.random() * 9000).toString(); // 4-digit numeric OTP
};

const sendOTP = async (phone, code) => {
    console.log(`Sending OTP ${code} to ${phone}`);
    // *** Replace this with actual SMS/email sending logic ***
    // Example with a hypothetical SMS service:
    // try {
    //     await smsService.send({
    //         to: phone,
    //         message: `Your Taqwa Home Delivery verification code is: ${code}`
    //     });
    //     return true;
    // } catch (error) {
    //     console.error('Error sending OTP:', error);
    //     return false;
    // }
    return true; // Simulate success for now
};

// --- API Routes ---

// @route   POST /register
// @desc    Register a new user
// @access  Public
app.post('/register', async (req, res) => {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !phone || !password) {
        return res.status(400).json({ error: 'All fields required' });
    }

    try {
        // Check if user already exists by email or phone
        let userByEmail = await User.findOne({ email });
        if (userByEmail) {
            return res.status(400).json({ error: 'User with this email already exists' });
        }
        let userByPhone = await User.findOne({ phone });
        if (userByPhone) {
            return res.status(400).json({ error: 'User with this phone number already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Generate OTP and expiry
        const verificationCode = generateOTP();
        const verificationCodeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now

        const user = new User({
            name,
            email,
            phone,
            password: hashedPassword,
            verificationCode,
            verificationCodeExpires
        });

        await user.save();

        // Send OTP (simulate for now)
        await sendOTP(phone, verificationCode);

        // Create JWT payload for immediate login
        const payload = {
            user: {
                id: user.id,
                role: user.role
            }
        };

        jwt.sign(
            payload,
            JWT_SECRET,
            { expiresIn: '1h' }, // Token expires in 1 hour
            (err, token) => {
                if (err) throw err;
                res.status(201).json({ 
                    message: 'User registered. Verification code sent.', 
                    token, 
                    name: user.name, 
                    email: user.email, 
                    phone: user.phone 
                });
            }
        );

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// @route   POST /login
// @desc    Authenticate user & get token
// @access  Public
app.post('/login', async (req, res) => {
    const { email, phone, password } = req.body; // Can login with email or phone
    if ((!email && !phone) || !password) {
        return res.status(400).json({ error: 'Email/Phone and password required' });
    }

    try {
        let user;
        if (email) {
            user = await User.findOne({ email });
        } else if (phone) {
            user = await User.findOne({ phone });
        }

        if (!user) {
            return res.status(400).json({ error: 'Invalid Credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password); // Compare with 'password' field

        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid Credentials' });
        }

        // Optional: Require verification before full login
        // if (!user.isVerified) {
        //     return res.status(400).json({ error: 'Please verify your phone number before logging in.' });
        // }

        // Create JWT payload
        const payload = {
            user: {
                id: user.id,
                role: user.role
            }
        };

        jwt.sign(
            payload,
            JWT_SECRET,
            { expiresIn: '7d' }, // Token expires in 7 days for better user experience
            (err, token) => {
                if (err) throw err;
                res.json({ token, name: user.name, email: user.email, phone: user.phone, address: user.address, role: user.role });
            }
        );

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// @route   POST /verify-phone
// @desc    Verify user's phone number with OTP
// @access  Private (requires token from registration or previous session)
app.post('/verify-phone', auth, async (req, res) => {
    const { code } = req.body; // OTP code from frontend
    const userId = req.user.id; // User ID from authenticated token

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.isVerified) {
            return res.status(400).json({ message: 'Phone already verified.' });
        }

        // Check if code matches and is not expired
        if (user.verificationCode === code && user.verificationCodeExpires > new Date()) {
            user.isVerified = true;
            user.verificationCode = undefined; // Clear code
            user.verificationCodeExpires = undefined; // Clear expiry
            await user.save();
            res.json({ message: 'Phone number successfully verified!' });
        } else {
            res.status(400).json({ error: 'Invalid or expired verification code.' });
        }

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error during phone verification' });
    }
});

// @route   POST /order
// @desc    Place a new order
// @access  Private (authenticated user)
app.post('/order', auth, async (req, res) => {
    const { product, qty, address, phone, message } = req.body;
    if (!product || !qty || !address || !phone) {
        return res.status(400).json({ error: 'Product, Quantity, Address, and Phone are required' });
    }

    const userId = req.user.id; // Get user ID from authenticated token

    try {
        // Fetch user's name (and potentially other details) for the order
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const newOrder = new Order({
            userId,
            userName: user.name, // Use the user's name
            product,
            qty,
            address,
            phone,
            message: message || '' // Optional message
        });

        await newOrder.save();
        res.status(201).json({ message: 'Order placed successfully!', order: newOrder });

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error placing order' });
    }
});

// @route   GET /orders
// @desc    Get all orders for the logged-in user
// @access  Private (authenticated user)
app.get('/orders', auth, async (req, res) => {
    const userId = req.user.id;

    try {
        const orders = await Order.find({ userId }).sort({ createdAt: -1 }); // Latest orders first
        res.json({ orders });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error fetching orders' });
    }
});

// @route   POST /order/cancel
// @desc    Cancel a specific order
// @access  Private (authenticated user)
app.post('/order/cancel', auth, async (req, res) => {
    const { orderId } = req.body;
    if (!orderId) {
        return res.status(400).json({ error: 'orderId required' });
    }

    const userId = req.user.id;

    try {
        const order = await Order.findOne({ _id: orderId, userId: userId });

        if (!order) {
            return res.status(404).json({ error: 'Order not found or you are not authorized to cancel this order.' });
        }

        if (order.status === 'Cancelled' || order.status === 'Delivered') {
            return res.status(400).json({ error: `Cannot cancel an order that is already ${order.status}.` });
        }

        order.status = 'Cancelled';
        await order.save();
        res.json({ message: 'Order cancelled successfully!', order });

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error cancelling order' });
    }
});

// @route   PUT /user/profile
// @desc    Update user profile
// @access  Private (authenticated user)
app.put('/user/profile', auth, async (req, res) => {
    const { name, email, phone, address } = req.body;
    const userId = req.user.id;

    try {
        let user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if new email/phone conflicts with existing users (excluding self)
        if (email && email !== user.email) {
            const existingEmail = await User.findOne({ email });
            if (existingEmail) {
                return res.status(400).json({ error: 'Email already in use by another account.' });
            }
        }
        if (phone && phone !== user.phone) {
            const existingPhone = await User.findOne({ phone });
            if (existingPhone) {
                return res.status(400).json({ error: 'Phone number already in use by another account.' });
            }
        }

        user.name = name || user.name;
        user.email = email || user.email;
        user.phone = phone || user.phone;
        user.address = address || user.address; // Address can be empty string initially

        await user.save();
        res.json({ message: 'Profile updated successfully!', user });

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error updating profile' });
    }
});

// --- Admin Routes ---

// @route   GET /admin/orders
// @desc    Get all orders (for admin dashboard)
// @access  Private (Admin only)
app.get('/admin/orders', auth, admin, async (req, res) => {
    try {
        const orders = await Order.find().sort({ createdAt: -1 }); // Latest orders first
        res.json({ orders });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error fetching admin orders' });
    }
});

// @route   PUT /admin/order/:id/status
// @desc    Update order status (e.g., Confirmed, Delivered)
// @access  Private (Admin only)
app.put('/admin/order/:id/status', auth, admin, async (req, res) => {
    const orderId = req.params.id;
    const { status } = req.body; // New status (e.g., 'Confirmed', 'Delivered')

    try {
        const order = await Order.findById(orderId);

        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }

        if (!['Pending', 'Confirmed', 'Delivered', 'Cancelled'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status provided.' });
        }

        order.status = status;
        await order.save();
        res.json({ message: `Order ${orderId} status updated to ${status}`, order });

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error updating order status' });
    }
});

// --- Basic Ping Route for Health Checks ---
app.get('/ping', (req, res) => {
    res.status(200).send('pong');
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
