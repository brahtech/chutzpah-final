const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- DATABASE CONNECTION ---
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: { rejectUnauthorized: false }
});

// --- INITIALIZE TABLES ---
async function initDB() {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Connected to TiDB Cloud Database securely!');
        
        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(20) DEFAULT 'customer',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS products (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                category VARCHAR(50) NOT NULL,
                price DECIMAL(10,2) NOT NULL,
                image_url TEXT,
                is_hidden BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id VARCHAR(50) PRIMARY KEY,
                user_id INT,
                customer_name VARCHAR(100),
                phone VARCHAR(20),
                items TEXT,
                total DECIMAL(10,2),
                status VARCHAR(20) DEFAULT 'PAID',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Default Admin (Phone: 0720470412, Pass: admin123)
        const [adminRows] = await connection.query("SELECT * FROM users WHERE role = 'admin'");
        if (adminRows.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await connection.query(
                "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
                ['Admin', '0720470412', hashedPassword, 'admin']
            );
            console.log('✅ Default Admin created (0720470412 / admin123)');
        }

        console.log('✅ Tables ready.');
        connection.release();
    } catch (err) {
        console.error('❌ Database error:', err.message);
    }
}
initDB();

// --- AUTHENTICATION MIDDLEWARE ---
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: "No token provided" });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: "Unauthorized" });
        req.user = decoded;
        next();
    });
};

// --- API ROUTES ---

// 1. REGISTER
app.post('/api/register', async (req, res) => {
    const { name, phone, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, phone, hashedPassword]
        );
        res.status(201).json({ success: true, message: "Account created!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Phone number already exists." });
    }
});

// 2. LOGIN
app.post('/api/login', async (req, res) => {
    const { phone, password } = req.body;
    try {
        const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [phone]);
        if (users.length === 0) return res.status(404).json({ message: "User not found" });

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ message: "Invalid password" });

        const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ success: true, token, user: { id: user.id, name: user.name, phone: user.email, role: user.role } });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// 3. GET ALL PRODUCTS
app.get('/api/products', async (req, res) => {
    try {
        const [products] = await pool.query("SELECT * FROM products WHERE is_hidden = FALSE ORDER BY created_at DESC");
        res.json(products);
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch products" });
    }
});

// 4. ADMIN: HIDE/SHOW PRODUCT
app.put('/api/products/:id/toggle', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Admin only" });
    const { is_hidden } = req.body;
    try {
        await pool.query("UPDATE products SET is_hidden = ? WHERE id = ?", [is_hidden, req.params.id]);
        res.json({ success: true, message: "Product visibility updated" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed to update" });
    }
});

// 5. ADMIN: UPDATE PRICE
app.put('/api/products/:id/price', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Admin only" });
    const { price } = req.body;
    try {
        await pool.query("UPDATE products SET price = ? WHERE id = ?", [price, req.params.id]);
        res.json({ success: true, message: "Price updated" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed to update price" });
    }
});

// 6. CREATE ORDER
app.post('/api/orders', async (req, res) => {
    const { orderId, customerName, phone, items, total } = req.body;
    try {
        await pool.query(
            "INSERT INTO orders (id, customer_name, phone, items, total) VALUES (?, ?, ?, ?, ?)",
            [orderId, customerName, phone, JSON.stringify(items), total]
        );
        res.status(201).json({ success: true, message: "Order saved!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed to save order" });
    }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Backend running on port ${PORT}`);
});
