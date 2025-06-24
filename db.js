const { Pool } = require('pg');

// Database connection configuration
const mainDbConfig = {
    connectionString: 'postgresql://gc_owner:npg_Lh9UmqVT7nGb@ep-wandering-flower-a1b4axgc-pooler.ap-southeast-1.aws.neon.tech/gc?sslmode=require'
};

let mainPool = null;

function getPool() {
    if (!mainPool) {
        mainPool = new Pool(mainDbConfig);
    }
    return mainPool;
}

async function initializeDatabase() {
    const pool = getPool();
    try {
        // Drop tables in correct order to handle foreign key constraints
        //await pool.query('DROP TABLE IF EXISTS messages CASCADE');
        //await pool.query('DROP TABLE IF EXISTS submissions CASCADE');
        //await pool.query('DROP TABLE IF EXISTS otps CASCADE');
        //await pool.query('DROP TABLE IF EXISTS users CASCADE');

        // Create users table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create OTP table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS otps (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                otp VARCHAR(6) NOT NULL,
                type VARCHAR(20) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                verified BOOLEAN DEFAULT FALSE,
                is_used BOOLEAN DEFAULT FALSE
            )
        `);

        // Create submissions table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS submissions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                ticket_user_name VARCHAR(255) NOT NULL,
                gc_code VARCHAR(255) NOT NULL,
                gc_phone VARCHAR(255) NOT NULL,
                ticket_number VARCHAR(255) NOT NULL,
                upi_id VARCHAR(255) NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                proof_video_url TEXT NOT NULL,
                status VARCHAR(50) NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Add status constraint
        await pool.query(`
            ALTER TABLE submissions 
            DROP CONSTRAINT IF EXISTS submissions_status_check;
            
            ALTER TABLE submissions 
            ADD CONSTRAINT submissions_status_check 
            CHECK (status IN ('pending', 'approved', 'rejected', 'paid', 'closed'));
        `);

        // Create messages table
        await pool.query(`
                CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                content TEXT NOT NULL,
                sender VARCHAR(50) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('Database tables initialized successfully');
    } catch (error) {
        console.error('Error initializing database:', error);
        throw error;
    }
}

async function closePool() {
    if (mainPool) {
        await mainPool.end();
        mainPool = null;
    }
}

module.exports = {
    getPool,
    initializeDatabase,
    closePool
};

// If this file is run directly, initialize the database
if (require.main === module) {
    initializeDatabase();
} 