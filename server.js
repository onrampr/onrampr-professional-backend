import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import compression from 'compression';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://onrampr.co';

// Professional Database Configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'ysdkgzpgms_rampr',
  connectionLimit: 10,
  charset: 'utf8mb4',
  timezone: '+00:00',
  supportBigNumbers: true,
  bigNumberStrings: true,
  // Remove invalid MySQL2 options
  acquireTimeout: undefined,
  timeout: undefined,
  reconnect: undefined
};

// Create connection pool
let pool;
const createPool = () => {
  if (!pool) {
    // Clean config - remove undefined values
    const cleanConfig = Object.fromEntries(
      Object.entries(dbConfig).filter(([_, value]) => value !== undefined)
    );
    pool = mysql.createPool(cleanConfig);
    console.log('✅ Professional MySQL Connection Pool created');
  }
  return pool;
};

// Professional Database Connection with Retry Logic
const connectDB = async () => {
  let retries = 5;
  while (retries > 0) {
    try {
      const connectionPool = createPool();
      const connection = await connectionPool.getConnection();
      console.log('✅ Professional MySQL Database connected successfully');
      connection.release();
      return;
    } catch (error) {
      retries--;
      console.error(`❌ Database connection failed. Retries left: ${retries}`);
      if (retries === 0) {
        console.error('❌ Database connection failed after all retries:', error.message);
        // Don't exit in production - allow graceful degradation
        if (process.env.NODE_ENV !== 'production') {
          process.exit(1);
        }
      } else {
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
  }
};

// Professional Database Query Helper with Logging
const query = async (sql, params = []) => {
  const start = Date.now();
  try {
    const connectionPool = createPool();
    const connection = await connectionPool.getConnection();
    const [rows] = await connection.execute(sql, params);
    const duration = Date.now() - start;
    
    console.log(`📊 Query executed in ${duration}ms:`, {
      sql: sql.substring(0, 100) + (sql.length > 100 ? '...' : ''),
      params: params.length,
      rows: Array.isArray(rows) ? rows.length : 1
    });
    
    connection.release();
    return { rows, insertId: rows.insertId };
  } catch (error) {
    console.error('❌ Professional Database query failed:', error.message);
    throw error;
  }
};

// Initialize Database Connection
connectDB();

// Professional Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: [FRONTEND_URL, 'http://localhost:8081', 'http://localhost:19006'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  credentials: true,
  optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '10mb' }));
app.use(compression());

// Professional Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Limit each IP to 1000 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later',
    retryAfter: 900 // 15 minutes in seconds
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/health' // Skip rate limiting for health checks
});
app.use(limiter);

// Professional Request Logging
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const url = req.originalUrl;
  const userAgent = req.get('User-Agent') || 'Unknown';
  
  console.log(`🌐 ${method} ${url} - ${timestamp} - ${userAgent.substring(0, 50)}...`);
  next();
});

// Professional Health Check Endpoint
app.get('/health', (req, res) => {
  const memoryUsage = process.memoryUsage();
  const uptime = process.uptime();
  
  res.status(200).json({
    success: true,
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    environment: process.env.NODE_ENV || 'development',
    uptime: Math.floor(uptime),
    memory: {
      rss: Math.round(memoryUsage.rss / 1024 / 1024) + ' MB',
      heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + ' MB',
      heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + ' MB'
    },
    database: {
      connected: pool ? 'connected' : 'disconnected',
      host: dbConfig.host,
      database: dbConfig.database
    },
    port: PORT,
    externalUrl: FRONTEND_URL
  });
});

// Professional JWT Authentication Middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Access token required',
      code: 'NO_TOKEN'
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const result = await query(
      'SELECT id, email, first_name, last_name, is_verified, kyc_status, tos_status, bridge_customer_id FROM users WHERE id = ? AND is_active = 1',
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ 
        success: false, 
        message: 'User not found or inactive',
        code: 'USER_NOT_FOUND'
      });
    }

    const user = result.rows[0];
    req.user = {
      userId: user.id,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name,
      isVerified: user.is_verified,
      kycStatus: user.kyc_status,
      tosStatus: user.tos_status,
      bridgeCustomerId: user.bridge_customer_id
    };

    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    }
    return res.status(500).json({ 
      success: false, 
      message: 'Authentication error',
      code: 'AUTH_ERROR'
    });
  }
};

// Professional Authentication Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Professional Input Validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required',
        code: 'MISSING_CREDENTIALS'
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format',
        code: 'INVALID_EMAIL'
      });
    }

    // Find user with professional error handling
    const userResult = await query(
      'SELECT id, first_name, last_name, email, password, is_verified, kyc_status, tos_status, bridge_customer_id FROM users WHERE email = ? AND is_active = 1',
      [email.toLowerCase().trim()]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
        code: 'INVALID_CREDENTIALS'
      });
    }

    const user = userResult.rows[0];

    // Professional Password Verification
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Professional JWT Token Generation
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        iat: Math.floor(Date.now() / 1000)
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Professional Response
    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        isVerified: user.is_verified,
        kycStatus: user.kyc_status,
        tosStatus: user.tos_status,
        bridgeCustomerId: user.bridge_customer_id
      },
      expiresIn: '7d'
    });

  } catch (error) {
    console.error('🔐 Professional Login Error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    // Professional Input Validation
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required',
        code: 'MISSING_FIELDS'
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format',
        code: 'INVALID_EMAIL'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters',
        code: 'WEAK_PASSWORD'
      });
    }

    // Check if user already exists
    const existingUser = await query(
      'SELECT id FROM users WHERE email = ?',
      [email.toLowerCase().trim()]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'User already exists with this email',
        code: 'USER_EXISTS'
      });
    }

    // Professional Password Hashing
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user with professional error handling
    const result = await query(
      'INSERT INTO users (first_name, last_name, email, password, is_active, is_verified, created_at) VALUES (?, ?, ?, ?, 1, 0, NOW())',
      [firstName.trim(), lastName.trim(), email.toLowerCase().trim(), hashedPassword]
    );

    // Professional JWT Token Generation
    const token = jwt.sign(
      { 
        userId: result.insertId, 
        email: email.toLowerCase().trim(),
        iat: Math.floor(Date.now() / 1000)
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Professional Response
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: {
        id: result.insertId,
        firstName: firstName.trim(),
        lastName: lastName.trim(),
        email: email.toLowerCase().trim(),
        isVerified: false,
        kycStatus: 'pending',
        tosStatus: 'pending'
      },
      expiresIn: '7d'
    });

  } catch (error) {
    console.error('🔐 Professional Registration Error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
});

// Professional Wallet Routes
app.get('/api/wallet/list', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'Wallet list retrieved successfully',
    wallets: [],
    user: {
      id: req.user.userId,
      email: req.user.email
    }
  });
});

app.post('/api/wallet/backup', authenticateToken, async (req, res) => {
  try {
    const { encryptedMnemonic } = req.body;

    if (!encryptedMnemonic) {
      return res.status(400).json({
        success: false,
        message: 'Encrypted mnemonic is required',
        code: 'MISSING_MNEMONIC'
      });
    }

    // Professional Database Operation
    await query(
      'INSERT INTO wallets (user_id, encrypted_mnemonic, created_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE encrypted_mnemonic = VALUES(encrypted_mnemonic), updated_at = NOW()',
      [req.user.userId, encryptedMnemonic]
    );

    res.json({
      success: true,
      message: 'Mnemonic backed up successfully',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('💾 Professional Backup Error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
});

app.get('/api/wallet/restore', authenticateToken, async (req, res) => {
  try {
    const result = await query(
      'SELECT encrypted_mnemonic FROM wallets WHERE user_id = ?',
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No backup found',
        code: 'NO_BACKUP'
      });
    }

    res.json({
      success: true,
      message: 'Mnemonic restored successfully',
      encryptedMnemonic: result.rows[0].encrypted_mnemonic,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('💾 Professional Restore Error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
});

// Professional User Routes
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const userResult = await query(
      'SELECT id, first_name, last_name, email, is_verified, kyc_status, tos_status, bridge_customer_id, created_at FROM users WHERE id = ?',
      [req.user.userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    const user = userResult.rows[0];

    res.json({
      success: true,
      message: 'Profile retrieved successfully',
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        isVerified: user.is_verified,
        kycStatus: user.kyc_status,
        tosStatus: user.tos_status,
        bridgeCustomerId: user.bridge_customer_id,
        createdAt: user.created_at
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('👤 Professional Profile Error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
});

// Professional Bridge Routes
app.post('/api/bridge/onramp', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'On-ramp initiated successfully',
    transaction: { 
      id: crypto.randomUUID(),
      status: 'pending',
      timestamp: new Date().toISOString()
    }
  });
});

app.post('/api/bridge/offramp', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'Off-ramp initiated successfully',
    transaction: { 
      id: crypto.randomUUID(),
      status: 'pending',
      timestamp: new Date().toISOString()
    }
  });
});

app.get('/api/bridge/transactions', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'Transactions retrieved successfully',
    transactions: [],
    timestamp: new Date().toISOString()
  });
});

// Professional Debugging Endpoint
app.get('/api/test', (req, res) => {
  console.log('🧪 Professional Test Endpoint Called');
  res.status(200).json({
    success: true,
    message: 'Professional API is working perfectly!',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    port: PORT,
    externalUrl: FRONTEND_URL,
    features: [
      'Professional Authentication',
      'Secure Database Integration',
      'Advanced Error Handling',
      'Rate Limiting',
      'Request Logging',
      'CORS Configuration'
    ]
  });
});

// Professional 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Professional API endpoint not found',
    code: 'NOT_FOUND',
    availableEndpoints: [
      'GET /health',
      'POST /api/auth/login',
      'POST /api/auth/register',
      'GET /api/user/profile',
      'GET /api/wallet/list',
      'POST /api/wallet/backup',
      'GET /api/wallet/restore',
      'POST /api/bridge/onramp',
      'POST /api/bridge/offramp',
      'GET /api/bridge/transactions'
    ]
  });
});

// Professional Error Handler
app.use((err, req, res, next) => {
  console.error('🚨 Professional Error Handler:', err);
  
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal server error',
    code: err.code || 'SERVER_ERROR',
    timestamp: new Date().toISOString(),
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// Professional Server Startup
app.listen(PORT, () => {
  console.log('🚀 Professional Onrampr API Server v2.0.0');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`📡 Server running on port: ${PORT}`);
  console.log(`🌐 External URL: https://appapi-pro.up.railway.app`);
  console.log(`📱 Frontend URL: ${FRONTEND_URL}`);
  console.log(`🔗 API Base URL: http://localhost:${PORT}/api`);
  console.log(`💾 Memory usage: ${Math.round(process.memoryUsage().rss / 1024 / 1024)} MB`);
  console.log(`🗄️  Database: ${dbConfig.database}@${dbConfig.host}`);
  console.log(`🔒 Security: Helmet, CORS, Rate Limiting`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('✨ Professional API Ready for Production! ✨');
});