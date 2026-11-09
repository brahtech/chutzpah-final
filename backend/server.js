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

// --- MIDDLEWARE ---
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

// 1. GET ALL PRODUCTS (Supports filtering by category & sub_category)
app.get('/api/products', async (req, res) => {
    try {
        const { category, sub_category } = req.query;
        let query = "SELECT * FROM products WHERE is_hidden = FALSE";
        let params = [];

        if (category) {
            query += " AND category = ?";
            params.push(category);
        }
        if (sub_category) {
            query += " AND sub_category = ?";
            params.push(sub_category);
        }

        query += " ORDER BY created_at DESC";
        const [products] = await pool.query(query, params);
        res.json(products);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Failed to fetch products" });
    }
});

// 2. ADD PRODUCT (Admin Only)
app.post('/api/products', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Admin access required" });

    const { name, category, sub_category, price, image_url } = req.body;

    try {
        await pool.query(
            "INSERT INTO products (name, category, sub_category, price, image_url) VALUES (?, ?, ?, ?, ?)",
            [name, category, sub_category || null, price, image_url]
        );
        res.status(201).json({ success: true, message: "Product added successfully!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Failed to add product" });
    }
});

// 3. UPDATE PRICE (Admin Only)
app.put('/api/products/:id/price', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Admin access required" });
    
    try {
        await pool.query("UPDATE products SET price = ? WHERE id = ?", [req.body.price, req.params.id]);
        res.json({ success: true, message: "Price updated" });
    } catch (err) { 
        res.status(500).json({ success: false, message: "Failed to update price" }); 
    }
});

// 4. HIDE/SHOW PRODUCT (Admin Only)
app.put('/api/products/:id/toggle', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Admin access required" });
    
    try {
        await pool.query("UPDATE products SET is_hidden = ? WHERE id = ?", [req.body.is_hidden, req.params.id]);
        res.json({ success: true, message: "Visibility updated" });
    } catch (err) { 
        res.status(500).json({ success: false, message: "Failed to update visibility" }); 
    }
});

// 5. LOGIN USER
app.post('/api/login', async (req, res) => {
    // Note: The frontend sends 'phone' but the DB column is called 'email'. We map it here.
    const phone = req.body.phone || req.body.email; 
    const password = req.body.password;

    try {
        const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [phone]);
        if (users.length === 0) return res.status(404).json({ message: "User not found" });
        
        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(401).json({ message: "Invalid password" });
        }
        
        const token = jwt.sign(
            { id: user.id, role: user.role, name: user.name }, 
            process.env.JWT_SECRET, 
            { expiresIn: '24h' }
        );
        
        res.json({ 
            success: true, 
            token, 
            user: { id: user.id, name: user.name, phone: user.email, role: user.role } 
        });
    } catch (err) { 
        res.status(500).json({ success: false, message: "Server error during login" }); 
    }
});

// 6. REGISTER USER
app.post('/api/register', async (req, res) => {
    const name = req.body.name;
    const phone = req.body.phone || req.body.email;
    const password = req.body.password;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
            [name, phone, hashedPassword]
        );
        res.status(201).json({ success: true, message: "Account created" });
    } catch (err) { 
        res.status(500).json({ success: false, message: "Phone number already exists" }); 
    }
});

// 7. CREATE ORDER
app.post('/api/orders', async (req, res) => {
    const { orderId, customerName, phone, items, total } = req.body;
    
    try {
        await pool.query(
            "INSERT INTO orders (id, customer_name, phone, items, total) VALUES (?, ?, ?, ?, ?)",
            [orderId, customerName, phone, JSON.stringify(items), total]
        );
        res.status(201).json({ success: true, message: "Order saved!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Failed to save order" });
    }
});

// --- START SERVER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Chutzpah Backend running on port ${PORT}`));
