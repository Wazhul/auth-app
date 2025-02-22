require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose
  .connect('mongodb://localhost:27017/auth_demo', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection error:", err));

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  age: { type: Number },
  dob: { type: Date },
  work: { type: String },
  mobile: { type: String },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  blocked: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);

// Middleware to verify JWT token
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // contains user id and role
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// Middleware for admin-only routes
const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// -----------------------------
// User Role Endpoints
// -----------------------------

// Register a new user
app.post('/register', async (req, res) => {
  try {
    const { name, email, age, dob, work, password, mobile } = req.body;
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create and save user (role defaults to 'user')
    const user = new User({ name, email, age, dob, work, mobile, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// User login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    if (user.blocked) return res.status(403).json({ message: 'User is blocked' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // Sign JWT with user id and role; expires in 1 hour
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get logged-in user's profile (excluding password)
app.get('/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// -----------------------------
// Admin Role Endpoints
// -----------------------------

// Admin login endpoint (admin users must be pre-created or manually set role to 'admin')
app.post('/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await User.findOne({ email, role: 'admin' });
    if (!admin) return res.status(400).json({ message: 'Invalid credentials or not an admin' });
    if (admin.blocked) return res.status(403).json({ message: 'Admin is blocked' });

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: admin._id, role: admin.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Admin: Get list of all users (excluding passwords)
app.get('/admin/users', authenticate, adminOnly, async (req, res) => {
  try {
    const users = await User.find({}).select('name email age dob work mobile');
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Admin: Delete a user by ID
app.delete('/admin/user/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    await User.findByIdAndDelete(id);
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Admin: Block a user (prevent login)
app.put('/admin/user/:id/block', authenticate, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findById(id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.blocked = true;
    await user.save();
    res.json({ message: 'User blocked successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// -----------------------------
// Protected Route Example
// -----------------------------
// This route is accessible only if a valid JWT is provided.
app.get('/protected', authenticate, (req, res) => {
  res.json({ message: "This is protected data", user: req.user });
});

// -----------------------------
// Start Server
// -----------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
