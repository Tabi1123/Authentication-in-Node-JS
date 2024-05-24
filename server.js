const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/user');
const Item = require('./models/item');

const app = express();
const port = 3000;
const jwtSecret = 'your_jwt_secret';

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/mydatabase', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Error connecting to MongoDB:', err));

// Auth routes
app.post('/auth/register', async (req, res) => {
    const { username, password, role } = req.body;
    try {
        const user = new User({ username, password, role });
        await user.save();
        res.status(201).send('User registered');
    } catch (error) {
        res.status(400).send('Error registering user');
    }
});

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).send('Invalid credentials');
        }
        const token = jwt.sign({ userId: user._id, role: user.role }, jwtSecret, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(400).send('Error logging in');
    }
});

// Middleware for authentication and authorization
const authMiddleware = async (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).send('Access denied');
    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.user = await User.findById(decoded.userId).select('-password');
        next();
    } catch (error) {
        res.status(400).send('Invalid token');
    }
};

const authorize = (roles = []) => {
    if (typeof roles === 'string') roles = [roles];
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) return res.status(403).send('Forbidden');
        next();
    };
};

// Item routes
app.post('/api/items', authMiddleware, authorize('admin'), async (req, res) => {
    try {
        const { name, description, quantity } = req.body;
        const item = new Item({ name, description, quantity });
        await item.save();
        res.status(201).json(item);
    } catch (error) {
        console.error('Error creating item:', error);
        res.status(500).send('Server error');
    }
});

app.get('/api/items', authMiddleware, async (req, res) => {
    try {
        const items = await Item.find();
        res.status(200).json(items);
    } catch (error) {
        console.error('Error retrieving items:', error);
        res.status(500).send('Server error');
    }
});

app.get('/api/items/:id', authMiddleware, async (req, res) => {
    try {
        const item = await Item.findById(req.params.id);
        if (!item) {
            return res.status(404).send('Item not found');
        }
        res.status(200).json(item);
    } catch (error) {
        console.error('Error retrieving item:', error);
        res.status(500).send('Server error');
    }
});

app.patch('/api/items/:id', authMiddleware, authorize('admin'), async (req, res) => {
    try {
        const { name, description, quantity } = req.body;
        const item = await Item.findByIdAndUpdate(req.params.id, { name, description, quantity }, { new: true });
        if (!item) {
            return res.status(404).send('Item not found');
        }
        res.status(200).json(item);
    } catch (error) {
        console.error('Error updating item:', error);
        res.status(500).send('Server error');
    }
});

app.delete('/api/items/:id', authMiddleware, authorize('admin'), async (req, res) => {
    try {
        const item = await Item.findByIdAndDelete(req.params.id);
        if (!item) {
            return res.status(404).send('Item not found');
        }
        res.status(200).send('Item deleted');
    } catch (error) {
        console.error('Error deleting item:', error);
        res.status(500).send('Server error');
    }
});

// Serve frontend
app.use(express.static('public'));

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
