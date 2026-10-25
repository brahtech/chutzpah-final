const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- CLOUDINARY CONFIGURATION ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer setup for temporary image storage in memory
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

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
        
        // Users Table
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

        // Products Table
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

        // Orders Table
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

        // Create default Admin
        const [adminRows] = await connection.query("SELECT * FROM users WHERE role = 'admin'");
        if (adminRows.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await connection.query(
                "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
                ['Admin', 'admin@chutzpah.com', hashedPassword, 'admin']
            );
            console.log('✅ Default Admin created (admin@chutzpah.com / admin123)');
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

// REGISTER USER
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword]
        );
        res.status(201).json({ success: true, message: "Account created!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Email already exists." });
    }
});

// LOGIN USER
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
        if (users.length === 0) return res.status(404).json({ message: "User not found" });

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ message: "Invalid password" });

        const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// GET ALL PRODUCTS (Public)
app.get('/api/products', async (req, res) => {
    try {
        const [products] = await pool.query("SELECT * FROM products WHERE is_hidden = FALSE ORDER BY created_at DESC");
        res.json(products);
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch products" });
    }
});

// ADMIN: ADD PRODUCT WITH IMAGE
app.post('/api/products', verifyToken, upload.single('image'), async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Admin only" });

    const { name, category, price } = req.body;
    let image_url = null;

    try {
        if (req.file) {
            const b64 = Buffer.from(req.file.buffer).toString("base64");
            let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
            const result = await cloudinary.uploader.upload(dataURI, { folder: "chutzpah_products" });
            image_url = result.secure_url;
        }

        await pool.query(
            "INSERT INTO products (name, category, price, image_url) VALUES (?, ?, ?, ?)",
            [name, category, price, image_url]
        );
        res.status(201).json({ success: true, message: "Product added!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Failed to add product" });
    }
});

// ADMIN: HIDE/SHOW PRODUCT
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

// CREATE ORDER
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
