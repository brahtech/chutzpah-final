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

// --- CLOUDINARY CONFIG ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer setup for temporary memory storage
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

// --- ROUTES ---

// 1. GET PRODUCTS
app.get('/api/products', async (req, res) => {
    try {
        const { category, sub_category } = req.query;
        let query = "SELECT * FROM products WHERE is_hidden = FALSE";
        let params = [];

        if (category) { query += " AND category = ?"; params.push(category); }
        if (sub_category) { query += " AND sub_category = ?"; params.push(sub_category); }

        query += " ORDER BY created_at DESC";
        const [products] = await pool.query(query, params);
        res.json(products);
    } catch (err) { res.status(500).json({ message: "Failed to fetch products" }); }
});

// 2. ADD PRODUCT (Handles both Cloudinary URL and File Upload)
app.post('/api/products', verifyToken, upload.single('image'), async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Admin only" });

    const { name, category, sub_category, price, image_url } = req.body;
    let final_image_url = image_url || null;

    try {
        // If a file was uploaded, send to Cloudinary
        if (req.file) {
            const b64 = Buffer.from(req.file.buffer).toString("base64");
            let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
            const result = await cloudinary.uploader.upload(dataURI, { folder: "chutzpah_products" });
            final_image_url = result.secure_url;
        }

        await pool.query(
            "INSERT INTO products (name, category, sub_category, price, image_url) VALUES (?, ?, ?, ?, ?)",
            [name, category, sub_category || null, price, final_image_url]
        );
        res.status(201).json({ success: true, message: "Product added!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Failed to add product" });
    }
});

// 3. UPDATE PRICE
app.put('/api/products/:id/price', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Admin only" });
    try {
        await pool.query("UPDATE products SET price = ? WHERE id = ?", [req.body.price, req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
});

// 4. TOGGLE HIDE/SHOW
app.put('/api/products/:id/toggle', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Admin only" });
    try {
        await pool.query("UPDATE products SET is_hidden = ? WHERE id = ?", [req.body.is_hidden, req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
});

// 5. AUTH
app.post('/api/login', async (req, res) => {
    const phone = req.body.phone || req.body.email; 
    const password = req.body.password;
    try {
        const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [phone]);
        if (users.length === 0) return res.status(404).json({ message: "User not found" });
        const user = users[0];
        if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ message: "Invalid password" });
        const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ success: true, token, user: { id: user.id, name: user.name, phone: user.email, role: user.role } });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.post('/api/register', async (req, res) => {
    const name = req.body.name;
    const phone = req.body.phone || req.body.email;
    const password = req.body.password;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, phone, hashedPassword]);
        res.status(201).json({ success: true });
    } catch (err) { res.status(500).json({ success: false, message: "Phone exists" }); }
});

// 6. ORDERS
app.post('/api/orders', async (req, res) => {
    const { orderId, customerName, phone, items, total } = req.body;
    try {
        await pool.query("INSERT INTO orders (id, customer_name, phone, items, total) VALUES (?, ?, ?, ?, ?)", [orderId, customerName, phone, JSON.stringify(items), total]);
        res.status(201).json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on ${PORT}`));
