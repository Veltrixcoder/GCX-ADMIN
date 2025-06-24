require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const multer = require('multer');
const { generateOtp, sendOtpEmail } = require('./mailService');
const { getPool, initializeDatabase, closePool } = require('./db');
const otpService = require('./otpService');
const axios = require('axios');
const http = require('http');
const socketIo = require('socket.io');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});
const port = process.env.PORT || 3000;

// Initialize database and start server
(async () => {
    try {
        await initializeDatabase();
        console.log('Database initialized successfully.');
        
        // Test database connection
        const pool = getPool();
        const client = await pool.connect();
        client.release();
        console.log('Connected to main database');
        
        server.listen(port, () => {
            console.log(`Server running on port ${port}`);
        });
    } catch (err) {
        console.error('Failed to initialize database or start server:', err);
        process.exit(1);
    }
})();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Store logs in memory (in production, use a database)
let serverLogs = [];

// Logging middleware
function logRequest(req, res, next) {
    const start = Date.now();
    
    // Log incoming request
    const requestLog = {
        type: 'request',
        message: `${req.method} ${req.path}`,
        details: {
            method: req.method,
            path: req.path,
            headers: req.headers,
            body: req.body,
            timestamp: new Date().toISOString(),
            ip: req.ip || req.connection.remoteAddress
        },
        source: 'middleware'
    };
    
    emitLog(requestLog);
    
    // Override res.end to log response
    const originalEnd = res.end;
    res.end = function(chunk, encoding) {
        const duration = Date.now() - start;
        
        const responseLog = {
            type: 'response',
            message: `${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`,
            details: {
                statusCode: res.statusCode,
                duration: duration,
                headers: res.getHeaders(),
                timestamp: new Date().toISOString()
            },
            source: 'middleware'
        };
        
        emitLog(responseLog);
        originalEnd.call(this, chunk, encoding);
    };
    
    next();
}

// Apply logging middleware
app.use(logRequest);

// Emit log to all connected clients
function emitLog(logData) {
    serverLogs.unshift(logData);
    
    // Keep only last 1000 logs
    if (serverLogs.length > 1000) {
        serverLogs = serverLogs.slice(0, 1000);
    }
    
    io.emit('server-log', logData);
}

// Manual logging function
function log(level, message, details = {}) {
    const logData = {
        type: level,
        message: message,
        details: {
            ...details,
            timestamp: new Date().toISOString()
        },
        source: 'server'
    };
    
    emitLog(logData);
    
    // Also log to console
    console.log(`[${level.toUpperCase()}] ${message}`, details);
}

// OTP Authentication middleware
const requireOtpAuth = async (req, res, next) => {
    const otp = req.headers['x-otp-token'];
    const email = req.headers['x-user-email'];

    if (!otp || !email) {
        return res.status(401).json({ error: 'Missing OTP or email headers' });
    }

    try {
        const pool = getPool();
        const result = await pool.query(
            'SELECT * FROM otps WHERE email = $1 AND otp = $2 AND verified = true AND expires_at > NOW()',
            [email, otp]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid or expired OTP' });
        }

        req.user = { email };
        next();
    } catch (err) {
        console.error('OTP verification error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// Admin OTP Authentication middleware
const requireAdminOtpAuth = async (req, res, next) => {
    try {
        const otp = req.headers['x-otp-token'];
        const email = req.headers['x-user-email'];

        if (!otp || !email) {
            return res.status(401).json({ 
                success: false, 
                error: 'Missing authentication headers' 
            });
        }

        const pool = getPool();
        // Verify OTP
        const result = await pool.query(
            'SELECT * FROM otps WHERE email = $1 AND otp = $2 AND is_used = false AND expires_at > NOW()',
            [email, otp]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid or expired OTP' 
            });
        }

        // Mark OTP as used
        await pool.query(
            'UPDATE otps SET is_used = true WHERE email = $1 AND otp = $2',
            [email, otp]
        );

        next();
    } catch (error) {
        console.error('Admin auth error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Authentication error' 
        });
    }
};

// Middleware to check OTP authentication
async function checkOtpAuth(req, res, next) {
  const otp = req.headers['x-otp-token'];
  const email = req.headers['x-user-email'];

  if (!otp || !email) {
    return res.status(401).json({ success: false, error: 'OTP token and email are required' });
  }

  try {
    const result = await otpService.verifyUserOtp(email, otp);
    if (!result.success) {
      return res.status(401).json({ success: false, error: 'Invalid OTP' });
    }
    next();
  } catch (error) {
    res.status(401).json({ success: false, error: error.message });
  }
}

// Middleware to check admin OTP authentication
async function checkAdminOtpAuth(req, res, next) {
    const otp = req.headers['x-otp-token'];
    
    if (!otp) {
        return res.status(401).json({ success: false, error: 'OTP token required' });
    }

    try {
        const response = await fetch('https://mail-steel.vercel.app/admin/verify-otp', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ otp })
        });

        const data = await response.json();
        if (!data.success) {
            return res.status(401).json({ success: false, error: 'Invalid OTP' });
        }

        next();
    } catch (error) {
        console.error('Admin OTP verification failed:', error);
        res.status(500).json({ success: false, error: 'Failed to verify admin OTP' });
    }
}

// Routes
app.get('/', (req, res) => {
    log('info', 'Homepage accessed', { 
        path: req.path, 
        userAgent: req.get('User-Agent'),
        ip: req.ip 
    });
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/status', (req, res) => {
    log('info', 'Status page accessed', { 
        path: req.path, 
        userAgent: req.get('User-Agent'),
        ip: req.ip 
    });
    res.sendFile(path.join(__dirname, 'public', 'status.html'));
});

app.get('/admin', (req, res) => {
    log('info', 'Admin page accessed', { 
        path: req.path, 
        userAgent: req.get('User-Agent'),
        ip: req.ip 
    });
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/server-logs', (req, res) => {
    log('info', 'Server logs page accessed', { 
        path: req.path, 
        userAgent: req.get('User-Agent'),
        ip: req.ip 
    });
    res.sendFile(path.join(__dirname, 'public', 'server-logs.html'));
});

// API Routes

// Send OTP
app.post('/api/send-otp', async (req, res) => {
  const { email, type } = req.body;
  
  if (!email && type !== 'admin') {
    return res.status(400).json({ success: false, error: 'Email is required for user OTP' });
  }

  try {
    let result;
    if (type === 'admin') {
      result = await otpService.sendAdminOtp();
  } else {
      result = await otpService.sendUserOtp(email);
    }
    res.json(result);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Verify OTP
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp, type } = req.body;
  
  if (!otp || (type !== 'admin' && !email)) {
    return res.status(400).json({ success: false, error: 'OTP and email (for user) are required' });
  }

  try {
    let result;
    if (type === 'admin') {
      result = await otpService.verifyAdminOtp(otp);
    } else {
      result = await otpService.verifyUserOtp(email, otp);
    }
    res.json(result);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Register new user
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ 
            success: false, 
            error: 'Name, email and password are required' 
        });
    }

    try {
        // Check if user already exists
        const { rows: existingUsers } = await getPool().query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email already registered' 
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const { rows: newUser } = await getPool().query(
            'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
            [name, email, hashedPassword]
        );

        res.json({ 
            success: true, 
            user: newUser[0],
            message: 'Registration successful' 
        });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to register user' 
        });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ 
            success: false, 
            error: 'Email and password are required' 
        });
    }

    try {
        const { rows: users } = await getPool().query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid email or password' 
            });
        }

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid email or password' 
            });
        }

        res.json({ 
            success: true, 
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Login failed' 
        });
    }
});

// Get user submissions (protected route example)
app.get('/api/user-submissions/:userId', checkOtpAuth, async (req, res) => {
  const { userId } = req.params;

  try {
    const result = await getPool().query(
      'SELECT * FROM submissions WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );
    res.json({ success: true, submissions: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch submissions' });
  }
});

// Gift Card Routes
app.post('/api/gift-cards', checkOtpAuth, async (req, res) => {
  const {
        ticket_user_name,
        ticket_number,
        gc_code,
        gc_phone,
        upi_id,
        amount,
        proof_video_url 
  } = req.body;
    const userId = req.headers['x-user-id'];

    if (!ticket_user_name || !ticket_number || !gc_code || !gc_phone || !upi_id || !amount || !proof_video_url) {
        return res.status(400).json({ 
            success: false, 
            error: 'All fields are required including the video URL' 
        });
  }

  try {
        const result = await getPool().query(
            `INSERT INTO submissions (
                user_id, 
                ticket_user_name,
                ticket_number,
                gc_code,
                gc_phone,
                upi_id,
                amount,
                proof_video_url
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
            [userId, ticket_user_name, ticket_number, gc_code, gc_phone, upi_id, amount, proof_video_url]
    );
        res.json({ 
            success: true, 
            submissionId: result.rows[0].id,
            message: 'Gift card submission successful'
        });
    } catch (error) {
        console.error('Gift card submission error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to submit gift card. Please try again.' 
        });
  }
});

// File2Link Upload Route
app.post('/api/upload', async (req, res) => {
    try {
        const formData = new FormData();
        formData.append('file', req.files.file);

        const response = await axios.post('https://file2link-ol4p.onrender.com/.com/upload', formData, {
            headers: {
                ...formData.getHeaders()
            }
        });

        if (response.data.success) {
            res.json({
                success: true,
                videoUrl: response.data.access_url
            });
        } else {
            throw new Error('Upload failed');
        }
    } catch (error) {
        console.error('File upload error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to upload file. Please try again.'
        });
  }
});

// Get chat messages
app.get('/api/messages/:userId', checkOtpAuth, async (req, res) => {
  const { userId } = req.params;
  const userEmail = req.headers['x-user-email'];

  try {
  // Verify that the user is requesting their own messages
    const userResult = await getPool().query('SELECT id FROM users WHERE email = $1', [userEmail]);
    if (userResult.rows.length === 0 || userResult.rows[0].id !== parseInt(userId)) {
      return res.status(403).json({ success: false, error: 'Unauthorized access' });
  }

    const result = await getPool().query(
      'SELECT * FROM messages WHERE user_id = $1 ORDER BY created_at ASC',
      [userId]
    );
    res.json({ success: true, messages: result.rows });
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch messages' });
  }
});

// Send message
app.post('/api/messages', checkOtpAuth, async (req, res) => {
  const { userId, content, sender } = req.body;
  const userEmail = req.headers['x-user-email'];

  if (!content || !sender) {
    return res.status(400).json({ success: false, error: 'Content and sender are required' });
  }

  try {
    // Verify that the user is sending a message to their own chat
    const userResult = await getPool().query('SELECT id FROM users WHERE email = $1', [userEmail]);
    if (userResult.rows.length === 0 || userResult.rows[0].id !== parseInt(userId)) {
      return res.status(403).json({ success: false, error: 'Unauthorized access' });
  }

    const result = await getPool().query(
      'INSERT INTO messages (user_id, content, sender) VALUES ($1, $2, $3) RETURNING *',
      [userId, content, sender]
    );
    res.json({ success: true, message: result.rows[0] });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ success: false, error: 'Failed to send message' });
  }
});

// Admin routes
app.get('/api/admin/users', async (req, res) => {
    try {
        const result = await getPool().query('SELECT id, email, created_at FROM users ORDER BY created_at DESC');
        res.json({ success: true, users: result.rows });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch users' });
    }
});

app.get('/api/admin/messages/all', async (req, res) => {
    try {
        const result = await getPool().query(`
            SELECT m.*, u.email as user_email 
            FROM messages m 
            JOIN users u ON m.user_id = u.id 
            ORDER BY m.created_at DESC
        `);
        res.json({ success: true, messages: result.rows });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch messages' });
    }
});

app.get('/api/admin/messages/:userId', async (req, res) => {
    const { userId } = req.params;
    try {
        const result = await getPool().query(
            'SELECT * FROM messages WHERE user_id = $1 ORDER BY created_at ASC',
            [userId]
        );
        res.json({ success: true, messages: result.rows });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch messages' });
    }
});

app.post('/api/admin/messages', async (req, res) => {
    try {
        const { userId, content } = req.body;
        await getPool().query(
            'INSERT INTO messages (user_id, content, sender) VALUES ($1, $2, $3)',
            [userId, content, 'admin']
        );
        res.json({ success: true });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ success: false, error: 'Failed to send message' });
    }
});

app.delete('/api/admin/messages/:messageId',  async (req, res) => {
    const { messageId } = req.params;
    try {
        await getPool().query('DELETE FROM messages WHERE id = $1', [messageId]);
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).json({ success: false, error: 'Failed to delete message' });
    }
});

app.delete('/api/admin/users/:userId',  async (req, res) => {
    const { userId } = req.params;
    try {
        // First delete all messages for the user
        await getPool().query('DELETE FROM messages WHERE user_id = $1', [userId]);
        // Then delete the user
        await getPool().query('DELETE FROM users WHERE id = $1', [userId]);
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ success: false, error: 'Failed to delete user' });
    }
});

app.get('/api/admin/submissions', async (req, res) => {
    try {
        const result = await getPool().query(`
            SELECT s.*, u.email as user_email 
            FROM submissions s 
            JOIN users u ON s.user_id = u.id 
            ORDER BY s.created_at DESC
        `);
        res.json({ success: true, submissions: result.rows });
    } catch (error) {
        console.error('Error fetching submissions:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch submissions' });
    }
});

// Update submission status
app.post('/api/admin/submissions/:submissionId/status', async (req, res) => {
    const { submissionId } = req.params;
    const { status } = req.body;

    // Validate status
    const validStatuses = ['pending', 'approved', 'rejected', 'paid', 'closed'];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ 
            success: false, 
            error: `Invalid status. Must be one of: ${validStatuses.join(', ')}` 
        });
    }

    try {
        // First check if submission exists
        const checkResult = await getPool().query(
            'SELECT * FROM submissions WHERE id = $1',
            [submissionId]
        );

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Submission not found' });
        }

        // Update submission status with a CASE statement to ensure valid status
        const updateResult = await getPool().query(
            `UPDATE submissions 
             SET status = CASE 
                WHEN $1 IN ('pending', 'approved', 'rejected', 'paid', 'closed') 
                THEN $1 
                ELSE status 
             END
             WHERE id = $2 
             RETURNING *`,
            [status, submissionId]
        );

        if (updateResult.rows.length === 0) {
            return res.status(500).json({ 
                success: false, 
                error: 'Failed to update submission status' 
            });
        }

        res.json({ 
            success: true, 
            submission: updateResult.rows[0],
            message: `Status updated to ${status}`
        });
    } catch (error) {
        console.error('Error updating submission status:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update submission status',
            details: error.message
        });
    }
});

// Get submission details including video proof
app.get('/api/admin/submissions/:submissionId', async (req, res) => {
    const { submissionId } = req.params;
    try {
        const result = await getPool().query(`
            SELECT s.*, u.email as user_email 
            FROM submissions s 
            JOIN users u ON s.user_id = u.id 
            WHERE s.id = $1
        `, [submissionId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Submission not found' });
        }
        
        res.json({ success: true, submission: result.rows[0] });
    } catch (error) {
        console.error('Error fetching submission details:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch submission details' });
    }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
    log('info', 'Client connected to server logs', { 
        socketId: socket.id,
        totalConnections: io.engine.clientsCount 
    });
    
    // Send existing logs to new client
    socket.emit('server-log', {
        type: 'info',
        message: 'Connected to server logs',
        details: { 
            socketId: socket.id,
            totalLogs: serverLogs.length 
        }
    });
    
    socket.on('disconnect', () => {
        log('info', 'Client disconnected from server logs', { 
            socketId: socket.id,
            totalConnections: io.engine.clientsCount 
        });
    });
    
    socket.on('request-logs', () => {
        log('info', 'Client requested historical logs', { socketId: socket.id });
        // Send last 100 logs
        const recentLogs = serverLogs.slice(0, 100);
        socket.emit('historical-logs', recentLogs);
    });
});

// Error handling
process.on('uncaughtException', (error) => {
    log('error', 'Uncaught Exception', { 
        error: error.message,
        stack: error.stack 
    });
});

process.on('unhandledRejection', (reason, promise) => {
    log('error', 'Unhandled Rejection', { 
        reason: reason,
        promise: promise 
    });
});

// Periodic system logs
setInterval(() => {
    const memoryUsage = process.memoryUsage();
    log('info', 'System status', {
        memory: {
            rss: Math.round(memoryUsage.rss / 1024 / 1024) + 'MB',
            heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB',
            heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB'
        },
        uptime: Math.round(process.uptime()) + 's',
        connections: io.engine.clientsCount
    });
}, 30000); // Every 30 seconds

module.exports = { app, server, io, log }; 
