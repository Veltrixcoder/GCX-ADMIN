const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const multer = require('multer');
const { getDb } = require('./db');
const otpService = require('./otpService');
const axios = require('axios');
const http = require('http');
const socketIo = require('socket.io');
const fs = require('fs');
const { ObjectId } = require('mongodb');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});
const port = 7860;

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files from React build directory
app.use(express.static(path.join(__dirname, 'public')));

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

// OTP Authentication middleware (MongoDB version)
const requireOtpAuth = async (req, res, next) => {
    const otp = req.headers['x-otp-token'];
    const email = req.headers['x-user-email'];

    if (!otp || !email) {
        return res.status(401).json({ error: 'Missing OTP or email headers' });
    }

    try {
        const db = await getDb();
        const result = await db.collection('otps').findOne({
            email,
            otp,
            verified: true,
            expires_at: { $gt: new Date() }
        });
        if (!result) {
            return res.status(401).json({ error: 'Invalid or expired OTP' });
        }
        req.user = { email };
        next();
    } catch (err) {
        console.error('OTP verification error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// Admin OTP Authentication middleware (MongoDB version)
const requireAdminOtpAuth = async (req, res, next) => {
    try {
        const otp = req.headers['x-otp-token'];
        const email = req.headers['x-user-email'];
        if (!otp || !email) {
            return res.status(401).json({ success: false, error: 'Missing authentication headers' });
        }
        const db = await getDb();
        const result = await db.collection('otps').findOne({
            email,
            otp,
            is_used: false,
            expires_at: { $gt: new Date() }
        });
        if (!result) {
            return res.status(401).json({ success: false, error: 'Invalid or expired OTP' });
        }
        await db.collection('otps').updateOne({ email, otp }, { $set: { is_used: true } });
        next();
    } catch (error) {
        console.error('Admin auth error:', error);
        res.status(500).json({ success: false, error: 'Authentication error' });
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

// Register new user (MongoDB version)
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ success: false, error: 'Name, email and password are required' });
    }
    try {
        const db = await getDb();
        const existingUser = await db.collection('users').findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, error: 'Email already registered' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await db.collection('users').insertOne({ name, email, password: hashedPassword, created_at: new Date() });
        res.json({ success: true, user: { id: result.insertedId, name, email }, message: 'Registration successful' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ success: false, error: 'Failed to register user' });
    }
});

// Login (MongoDB version)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, error: 'Email and password are required' });
    }
    try {
        const db = await getDb();
        const user = await db.collection('users').findOne({ email });
        if (!user) {
            return res.status(401).json({ success: false, error: 'Invalid email or password' });
        }
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ success: false, error: 'Invalid email or password' });
        }
        res.json({ success: true, user: { id: user._id, name: user.name, email: user.email } });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ success: false, error: 'Login failed' });
    }
});

// Get user submissions (MongoDB version)
app.get('/api/user-submissions/:userId', checkOtpAuth, async (req, res) => {
    const { userId } = req.params;
    try {
        const db = await getDb();
        const userIdObj = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;
        const submissions = await db.collection('submissions').find({ user_id: userIdObj }).sort({ created_at: -1 }).toArray();
        const mappedSubs = submissions.map(sub => {
            const payment_address = sub.payment_address || sub.upi_id || 'oldsub';
            const mapped = {
                ...sub,
                payment_address,
                card_type: sub.card_type || 'oldsub',
                payment_method: sub.payment_method || 'oldsub'
            };
            delete mapped.upi_id;
            return mapped;
        });
        res.json({ success: true, submissions: mappedSubs });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to fetch submissions' });
    }
});

// Gift Card Submission (MongoDB version)
app.post('/api/gift-cards', checkOtpAuth, async (req, res) => {
    const { ticket_user_name, gc_code, gc_phone, ticket_number, payment_address, amount, proof_video_url, card_type, payment_method } = req.body;
    const userId = req.headers['x-user-id'];
    const finalTicketNumber = ticket_number || `TKT-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    if (!ticket_user_name || !gc_code || !gc_phone || !payment_address || !amount || !proof_video_url || !card_type || !payment_method) {
        return res.status(400).json({ success: false, error: 'All fields are required including the video URL, card type, payment address, and payment method' });
    }
    try {
        const db = await getDb();
        const userIdObj = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;
        const result = await db.collection('submissions').insertOne({
            user_id: userIdObj,
            ticket_user_name,
            gc_code,
            gc_phone,
            ticket_number: finalTicketNumber,
            payment_address,
            amount,
            proof_video_url,
            card_type,
            payment_method,
            status: 'pending',
            created_at: new Date(),
            updated_at: new Date()
        });
        res.json({ success: true, submissionId: result.insertedId, message: 'Gift card submission successful' });
    } catch (error) {
        console.error('Gift card submission error:', error);
        res.status(500).json({ success: false, error: 'Failed to submit gift card. Please try again.' });
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

// Get chat messages (MongoDB version)
app.get('/api/messages/:userId', checkOtpAuth, async (req, res) => {
    const { userId } = req.params;
    const userEmail = req.headers['x-user-email'];
    try {
        const db = await getDb();
        const user = await db.collection('users').findOne({ email: userEmail });
        // Allow legacy numeric id or ObjectId string
        const userIdStr = userId.toString();
        const userIdObj = ObjectId.isValid(userIdStr) ? new ObjectId(userIdStr) : userIdStr;
        if (!user || (user._id.toString() !== userIdStr && user.id?.toString() !== userIdStr)) {
            return res.status(403).json({ success: false, error: 'Unauthorized access' });
        }
        const messages = await db.collection('messages').find({ $or: [ { user_id: userIdObj }, { user_id: user.id } ] }).sort({ created_at: 1 }).toArray();
        res.json({ success: true, messages });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch messages' });
    }
});

// Send message (MongoDB version)
app.post('/api/messages', checkOtpAuth, async (req, res) => {
    const { userId, content, sender } = req.body;
    const userEmail = req.headers['x-user-email'];
    if (!content || !sender) {
        return res.status(400).json({ success: false, error: 'Content and sender are required' });
    }
    try {
        const db = await getDb();
        const user = await db.collection('users').findOne({ email: userEmail });
        const userIdStr = userId.toString();
        const userIdObj = ObjectId.isValid(userIdStr) ? new ObjectId(userIdStr) : userIdStr;
        if (!user || (user._id.toString() !== userIdStr && user.id?.toString() !== userIdStr)) {
            return res.status(403).json({ success: false, error: 'Unauthorized access' });
        }
        const result = await db.collection('messages').insertOne({ user_id: userIdObj, content, sender, created_at: new Date() });
        res.json({ success: true, message: { ...result.ops?.[0], user_id: userId, id: userId, _id: result.insertedId } });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ success: false, error: 'Failed to send message' });
    }
});

// Admin routes (MongoDB version)
app.get('/api/admin/users', async (req, res) => {
    try {
        const db = await getDb();
        const users = await db.collection('users').find({}, { projection: { password: 0 } }).sort({ created_at: -1 }).toArray();
        res.json({ success: true, users });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch users' });
    }
});

app.get('/api/admin/messages/all', async (req, res) => {
    try {
        const db = await getDb();
        const messages = await db.collection('messages').find({}).sort({ created_at: -1 }).toArray();
        res.json({ success: true, messages });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch messages' });
    }
});

app.get('/api/admin/messages/:userId', async (req, res) => {
    const { userId } = req.params;
    try {
        const db = await getDb();
        const userIdObj = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;
        const messages = await db.collection('messages').find({ user_id: userIdObj }).sort({ created_at: 1 }).toArray();
        res.json({ success: true, messages });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch messages' });
    }
});

app.post('/api/admin/messages', async (req, res) => {
    try {
        const { userId, content } = req.body;
        const db = await getDb();
        const result = await db.collection('messages').insertOne({ user_id: userId, content, sender: 'admin', created_at: new Date() });
        res.json({ success: true });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ success: false, error: 'Failed to send message' });
    }
});

app.delete('/api/admin/messages/:messageId',  async (req, res) => {
    const { messageId } = req.params;
    try {
        const db = await getDb();
        await db.collection('messages').deleteOne({ _id: messageId });
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).json({ success: false, error: 'Failed to delete message' });
    }
});

app.delete('/api/admin/users/:userId',  async (req, res) => {
    const { userId } = req.params;
    try {
        const db = await getDb();
        const userIdObj = ObjectId.isValid(userId) ? new ObjectId(userId) : userId;
        // First delete all messages for the user
        await db.collection('messages').deleteMany({ user_id: userIdObj });
        // Then delete the user
        await db.collection('users').deleteOne({ _id: userIdObj });
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ success: false, error: 'Failed to delete user' });
    }
});

app.get('/api/admin/submissions', async (req, res) => {
    try {
        const db = await getDb();
        const submissions = await db.collection('submissions').find({}).sort({ created_at: -1 }).toArray();
        const mappedSubs = submissions.map(sub => {
          const payment_address = sub.payment_address || sub.upi_id || 'oldsub';
          const mapped = {
            ...sub,
            payment_address,
            card_type: sub.card_type || 'oldsub',
            payment_method: sub.payment_method || 'oldsub'
          };
          delete mapped.upi_id;
          return mapped;
        });
        res.json({ success: true, submissions: mappedSubs });
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
        const db = await getDb();
        // Convert submissionId to ObjectId
        const submissionIdObj = ObjectId.isValid(submissionId) ? new ObjectId(submissionId) : submissionId;
        // First check if submission exists
        const checkResult = await db.collection('submissions').findOne({ _id: submissionIdObj });

        if (!checkResult) {
            return res.status(404).json({ success: false, error: 'Submission not found' });
        }

        // Update submission status
        const updateResult = await db.collection('submissions').updateOne(
            { _id: submissionIdObj },
            { $set: { status: status, updated_at: new Date() } }
        );

        if (updateResult.matchedCount === 0) {
            return res.status(500).json({ 
                success: false, 
                error: 'Failed to update submission status' 
            });
        }

        res.json({ 
            success: true, 
            submission: updateResult.value,
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
        const db = await getDb();
        // Convert submissionId to ObjectId
        const submissionIdObj = ObjectId.isValid(submissionId) ? new ObjectId(submissionId) : submissionId;
        const submission = await db.collection('submissions').findOne({ _id: submissionIdObj });
        
        if (!submission) {
            return res.status(404).json({ success: false, error: 'Submission not found' });
        }
        // Ensure card_type, payment_method, and payment_address are always present, and remove upi_id
        const payment_address = submission.payment_address || submission.upi_id || 'oldsub';
        const submissionDetails = {
          ...submission,
          payment_address,
          card_type: submission.card_type || 'oldsub',
          payment_method: submission.payment_method || 'oldsub'
        };
        delete submissionDetails.upi_id;
        res.json({ success: true, submission: submissionDetails });
    } catch (error) {
        console.error('Error fetching submission details:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch submission details' });
    }
});

// Utility endpoint to update old submissions: set card_type and payment_method to 'oldsub' where missing
app.post('/api/admin/fix-old-submissions', async (req, res) => {
    try {
        const db = await getDb();
        const result = await db.collection('submissions').updateMany(
            {
                $or: [
                    { card_type: { $in: [null, ''] } },
                    { payment_method: { $in: [null, ''] } }
                ]
            },
            { $set: { card_type: 'oldsub', payment_method: 'oldsub' } }
        );
        res.json({
            success: true,
            updatedCount: result.modifiedCount
        });
    } catch (error) {
        console.error('Error updating old submissions:', error);
        res.status(500).json({ success: false, error: 'Failed to update old submissions' });
    }
});

// Check if submission is open (Sunday 9am-9pm)
app.get('/isubmissionopen', (req, res) => {
    const now = new Date();
    const dayOfWeek = now.getDay(); // 0 = Sunday, 1 = Monday, ..., 6 = Saturday
    const hour = now.getHours();
    
    // Check if it's Sunday (day 0) and between 9am (9) and 9pm (21)
    const isSubmissionOpen = dayOfWeek === 0 && hour >= 9 && hour < 21;
    
    log('info', 'Submission status checked', { 
        dayOfWeek: dayOfWeek,
        hour: hour,
        isOpen: isSubmissionOpen,
        ip: req.ip 
    });
    
    res.json({ 
        success: true, 
        isSubmissionOpen: true,
        currentTime: now.toISOString(),
        dayOfWeek: dayOfWeek,
        hour: hour
    });
});

// Catch-all route for React Router - serve index.html for all non-API routes
app.get('*', (req, res) => {
    // Skip API routes
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API endpoint not found' });
    }
    
    // Skip the /isubmissionopen endpoint
    if (req.path === '/isubmissionopen') {
        return res.status(404).json({ error: 'Endpoint not found' });
    }
    
    log('info', 'React route accessed', { 
        path: req.path, 
        userAgent: req.get('User-Agent'),
        ip: req.ip 
    });
    
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
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

server.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

module.exports = app; 
