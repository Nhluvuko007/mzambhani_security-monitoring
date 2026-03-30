const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json());

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // 1. Check if username matches our .env admin
    if (username !== process.env.ADMIN_USER) {
        return res.status(401).json({ message: "Invalid Credentials" });
    }

    // 2. Check if password matches our .env admin password 
    if (password !== process.env.ADMIN_PASS) {
        return res.status(401).json({ message: "Invalid Credentials" });
    }

    // 3. Create a JWT Token that expires in 1 hour
    const token = jwt.sign(
        { role: 'admin', user: username },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    res.json({ token, role: 'admin' });
});

console.log("Checking Environment Variables...");
console.log("User:", process.env.DB_USER);
console.log("Pass:", process.env.DB_PASS ? "Found" : "Missing");
console.log("Cluster:", process.env.DB_CLUSTER);

if (!process.env.DB_USER || !process.env.DB_PASS || !process.env.DB_CLUSTER) {
    console.error("❌ ERROR: One or more environment variables are missing from your .env file!");
    process.exit(1); 
}

// --- SECURE ENCODING LOGIC ---
const user = encodeURIComponent(process.env.DB_USER);
const pass = encodeURIComponent(process.env.DB_PASS);
const cluster = process.env.DB_CLUSTER;
const dbName = process.env.DB_NAME;

// Construct the URI dynamically and securely
const MONGO_URI = `mongodb://${user}:${pass}@${cluster}/${dbName}?ssl=true&replicaSet=atlas-otm1pb-shard-0&authSource=admin&retryWrites=true&w=majority`;

// 1. Connect to MongoDB
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ Connected to SecurityDB"))
  .catch(err => console.error("❌ Connection error:", err));

// 2. Define the Alert Schema (Matches your Python data)
const AlertSchema = new mongoose.Schema({
    ip: String,
    attempts: Number,
    timestamp: String,
    type: String,
    severity: String
});

const Alert = mongoose.model('Alert', AlertSchema, 'alerts');

// Middleware to check if user is an Admin
const verifyAdmin = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: "No token provided" });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: "Unauthorized" });
        req.user = decoded;
        next();
    });
};

// Alerts route for alerts
app.get('/api/alerts', verifyAdmin, async (req, res) => {
    const alerts = await Alert.find().sort({ _id: -1 });
    res.json(alerts);
});

// 1. Define the Scan Schema (Matches your Phish-Tank data)
const ScanSchema = new mongoose.Schema({
    url: String,
    malicious_count: Number,
    total_engines: Number,
    scan_date: { type: String, default: () => new Date().toLocaleString() }
});
const Scan = mongoose.model('Scan', ScanSchema, 'url_scans');

// 2. Scan route to see past scans
app.get('/api/scans', async (req, res) => {
    const scans = await Scan.find().sort({ _id: -1 });
    res.json(scans);
});

// 3. POST route to save a NEW scan from the UI
app.post('/api/scans', async (req, res) => {
    const { url } = req.body;
    const apiKey = process.env.VT_API_KEY;

    try {
        // 1. Call VirusTotal API
        const vtResponse = await axios.get(
            `https://www.virustotal.com/api/v3/domains/${new URL(url).hostname}`,
            { headers: { 'x-apikey': apiKey } }
        );

        const stats = vtResponse.data.data.attributes.last_analysis_stats;
        
        // 2. Prepare the real data
        const newScan = new Scan({
            url: url,
            malicious_count: stats.malicious,
            total_engines: stats.malicious + stats.harmless + stats.undetected,
            scan_date: new Date().toLocaleString()
        });

        // 3. Save to MongoDB
        await newScan.save();
        res.status(201).json(newScan);
    } catch (err) {
        console.error("VT API Error:", err.message);
        res.status(500).json({ message: "Failed to scan URL" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));