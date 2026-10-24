const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Database connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: { rejectUnauthorized: false } // Required for TiDB Cloud
});

// Test database connection and create tables
async function initDB() {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Connected to TiDB Cloud Database securely!');
        
        // Create a basic table for orders
        await connection.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id VARCHAR(50) PRIMARY KEY,
                customer_name VARCHAR(100),
                phone VARCHAR(20),
                items TEXT,
                total DECIMAL(10,2),
                status VARCHAR(20) DEFAULT 'PAID',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Orders table ready.');
        connection.release();
    } catch (err) {
        console.error('❌ Database connection failed:', err.message);
    }
}
initDB();

// --- API ROUTES ---

// 1. Test Route (to check if backend is live)
app.get('/', (req, res) => {
    res.json({ message: "Chutzpah Enterprises API is running perfectly!" });
});

// 2. Admin Login Route
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === 'admin123') {
        res.json({ success: true, token: process.env.JWT_SECRET, message: "Login successful" });
    } else {
        res.status(401).json({ success: false, message: "Invalid credentials" });
    }
});

// 3. Create a New Order
app.post('/api/orders', async (req, res) => {
    const { orderId, customerName, phone, items, total } = req.body;
    try {
        await pool.query(
            'INSERT INTO orders (id, customer_name, phone, items, total) VALUES (?, ?, ?, ?, ?)',
            [orderId, customerName, phone, JSON.stringify(items), total]
        );
        res.status(201).json({ success: true, message: "Order saved to database" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Failed to save order" });
    }
});

// 4. Get All Orders (For Admin Dashboard)
app.get('/api/orders', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM orders ORDER BY created_at DESC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed to fetch orders" });
    }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Backend server running on port ${PORT}`);
});
