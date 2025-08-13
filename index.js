const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "secretkey";

app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
.then(() => console.log("MongoDB connected"))
.catch(err => console.error(err));

// User schema and model
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  passwordHash: String
});
const User = mongoose.model('User', userSchema);

// Order schema and model
const orderSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  product: String,
  qty: String, // now qty can store text like "H", "Sg", "10", etc.
  address: String,
  phone: String,
  status: { type: String, default: "Placed" },
  createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

// Middleware to authenticate using JWT
const auth = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if(!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};

// Routes

// Register
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if(!name || !email || !password) return res.status(400).json({ error: "All fields required" });

  const existingUser = await User.findOne({ email });
  if(existingUser) return res.status(400).json({ error: "Email already registered" });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = new User({ name, email, passwordHash });
  await user.save();
  res.json({ message: "Registered successfully" });
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if(!email || !password) return res.status(400).json({ error: "All fields required" });

  const user = await User.findOne({ email });
  if(!user) return res.status(400).json({ error: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if(!valid) return res.status(400).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user._id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, name: user.name, email: user.email });
});

// Place order (authenticated)
app.post('/order', auth, async (req, res) => {
  const { product, qty, address, phone } = req.body;
  if(!product || !qty || !address || !phone) return res.status(400).json({ error: "All fields required" });

  const order = new Order({
    userId: req.user.id,
    product,
    qty,
    address,
    phone
  });
  await order.save();
  res.json({ message: "Order placed", orderId: order._id });
});

// Get orders for logged in user
app.get('/orders', auth, async (req, res) => {
  const orders = await Order.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json({ orders });
});

// Cancel order
app.post('/order/cancel', auth, async (req, res) => {
  const { orderId } = req.body;
  if(!orderId) return res.status(400).json({ error: "orderId required" });

  const order = await Order.findOne({ _id: orderId, userId: req.user.id });
  if(!order) return res.status(404).json({ error: "Order not found" });

  if(order.status === "Cancelled") return res.status(400).json({ error: "Order already cancelled" });

  order.status = "Cancelled";
  await order.save();
  res.json({ message: "Order cancelled" });
});
// Add this just before app.listen
app.get('/ping', (req, res) => {
  res.status(200).send('pong');
});
// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
