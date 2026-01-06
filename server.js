const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/admin-takeover-lab');

// Schemas
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  firstName: String,
  lastName: String,
  phone: String,
  address: String,
  city: String,
  zipCode: String,
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const otpSchema = new mongoose.Schema({
  email: String,
  otp: String,
  createdAt: { type: Date, default: Date.now, expires: 30 }
});

const User = mongoose.model('User', userSchema);
const OTP = mongoose.model('OTP', otpSchema);

// Swagger setup
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'TechIndustries Admin API',
      version: '1.0.0',
      description: 'Internal Admin API for TechIndustries'
    },
    servers: [
      {
        url: 'http://localhost:3000',
        description: 'Development server'
      }
    ]
  },
  apis: ['./server.js']
};

const specs = swaggerJsdoc(swaggerOptions);

// Routes
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.get('/register', (req, res) => {
  res.sendFile(__dirname + '/public/register.html');
});

app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/public/login.html');
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.sendFile(__dirname + '/public/dashboard.html');
});

app.get('/email-client', (req, res) => {
  res.sendFile(__dirname + '/public/email-client.html');
});

app.get('/jerry.gif', (req, res) => {
  res.sendFile(__dirname + '/public/jerry.gif');
});


app.get('/product.png', (req, res) => {
  res.sendFile(__dirname + '/public/product.png');
});

// Get all OTPs for email client
app.get('/api/otps', async (req, res) => {
  try {
    const otps = await OTP.find({}).sort({ createdAt: -1 });
    res.json(otps);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// OTP endpoint for testing
app.get('/otp/:email', async (req, res) => {
  try {
    const otp = await OTP.findOne({ email: req.params.email });
    if (otp) {
      res.json({ email: req.params.email, otp: otp.otp, expiresIn: '30 seconds' });
    } else {
      res.json({ message: 'No OTP found' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Send OTP
app.post('/api/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    await OTP.deleteMany({ email });
    await OTP.create({ email, otp });
    
    res.json({ success: true, message: 'OTP sent successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verify OTP
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const otpRecord = await OTP.findOne({ email, otp });
    
    if (otpRecord) {
      req.session.verifiedEmail = email;
      res.json({ success: true });
    } else {
      res.json({ success: false, message: 'Invalid OTP' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Complete registration
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName, phone, address, city, zipCode } = req.body;
    
    if (req.session.verifiedEmail !== email) {
      return res.status(400).json({ error: 'Email not verified' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const isAdmin = email.endsWith('@teghindustries.com');
    
    const user = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      phone,
      address,
      city,
      zipCode,
      isAdmin
    });
    
    await user.save();
    req.session.user = { id: user._id, email: user.email, isAdmin: user.isAdmin };
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (user && await bcrypt.compare(password, user.password)) {
      req.session.user = { id: user._id, email: user.email, isAdmin: user.isAdmin };
      res.json({ success: true });
    } else {
      res.json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user info
app.get('/api/user', (req, res) => {
  if (req.session.user) {
    res.json(req.session.user);
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

// Admin middleware
const adminOnly = (req, res, next) => {
  if (req.session.user && req.session.user.isAdmin) {
    next();
  } else {
    res.status(403).json({ error: 'Admin access required' });
  }
};

/**
 * @swagger
 * /api/send-otp:
 *   post:
 *     summary: Send OTP to email
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *     responses:
 *       200:
 *         description: OTP sent successfully
 */

/**
 * @swagger
 * /api/verify-otp:
 *   post:
 *     summary: Verify OTP code
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               otp:
 *                 type: string
 *     responses:
 *       200:
 *         description: OTP verified successfully
 */

/**
 * @swagger
 * /api/register:
 *   post:
 *     summary: Complete user registration
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               phone:
 *                 type: string
 *               address:
 *                 type: string
 *               city:
 *                 type: string
 *               zipCode:
 *                 type: string
 *     responses:
 *       200:
 *         description: User registered successfully
 */

/**
 * @swagger
 * /api/login:
 *   post:
 *     summary: User login
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 */

/**
 * @swagger
 * /api/user:
 *   get:
 *     summary: Get current user info
 *     responses:
 *       200:
 *         description: Current user information
 *       401:
 *         description: Not authenticated
 */

/**
 * @swagger
 * /api/logout:
 *   post:
 *     summary: User logout
 *     responses:
 *       200:
 *         description: Logout successful
 */

/**
 * @swagger
 * /api/otps:
 *   get:
 *     summary: Get all OTPs (for testing)
 *     responses:
 *       200:
 *         description: List of all OTPs
 */

/**
 * @swagger
 * /otp/{email}:
 *   get:
 *     summary: Get OTP for specific email (testing endpoint)
 *     parameters:
 *       - in: path
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: OTP details
 */

/**
 * @swagger
 * /api/users/all:
 *   get:
 *     summary: Get all registered users (Admin only)
 *     responses:
 *       200:
 *         description: List of all users
 *       403:
 *         description: Admin access required
 */

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Get user by ID (Admin only)
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User details
 *       403:
 *         description: Admin access required
 *       404:
 *         description: User not found
 */
app.get('/api/users/all', adminOnly, async (req, res) => {
  try {
    const users = await User.find({}, '-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Get user by ID (Admin only)
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User details
 *       403:
 *         description: Admin access required
 *       404:
 *         description: User not found
 */
app.get('/api/users/:id', adminOnly, async (req, res) => {
  try {
    const user = await User.findById(req.params.id, '-password');
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});



// Swagger UI (Admin only)
app.get('/internal/swagger/index.html', (req, res) => {
  const html = `
<!DOCTYPE html>
<html>
<head>
  <title>TechIndustries Admin API</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.0.0/swagger-ui.css" />
  <style>
    .swagger-ui .topbar { display: none }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.0.0/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5.0.0/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: '/api/swagger.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout"
      });
    };
  </script>
</body>
</html>`;
  res.send(html);
});

// Serve swagger JSON
app.get('/api/swagger.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(specs);
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Homepage: http://localhost:${PORT}`);
  console.log(`Admin API: http://localhost:${PORT}/internal/swagger/index.html`);
});
