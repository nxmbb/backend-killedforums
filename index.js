require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}


// Register user (no email)
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Validate input
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password' });
  }

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database
    const [result] = await pool.query(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );

    // Respond with success
    res.json({ message: 'User registered', userId: result.insertId });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Username already exists' });
    }
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});


// Login user
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) return res.status(400).json({ error: 'Invalid credentials' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get all threads
app.get('/threads', async (req, res) => {
  try {
    const { category } = req.query;
    let sql = `
      SELECT t.id, t.title, t.content, t.created_at, t.category, u.username
      FROM threads t
      JOIN users u ON t.user_id = u.id
    `;
    const params = [];
    if (category) {
      sql += ' WHERE t.category = ?';
      params.push(category);
    }
    sql += ' ORDER BY t.created_at DESC';

    const [threads] = await pool.query(sql, params);
    res.json(threads);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});


// Get a thread by id + its posts
app.get('/threads/:id', async (req, res) => {
  const threadId = req.params.id;
  try {
    const [[thread]] = await pool.query(`
      SELECT t.id, t.title, t.content, t.created_at, u.username
      FROM threads t
      JOIN users u ON t.user_id = u.id
      WHERE t.id = ?
    `, [threadId]);
    
    if (!thread) return res.status(404).json({ error: 'Thread not found' });

    const [posts] = await pool.query(`
      SELECT p.id, p.content, p.created_at, u.username
      FROM posts p
      JOIN users u ON p.user_id = u.id
      WHERE p.thread_id = ?
      ORDER BY p.created_at ASC
    `, [threadId]);

    res.json({ thread, posts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});


// Create a thread (authenticated)
app.post('/createthreads', authenticateToken, async (req, res) => {
  const { title, content, category } = req.body;
  if (!title || !content || !category) return res.status(400).json({ error: 'Missing fields' });

  try {
    const [result] = await pool.query(
      'INSERT INTO threads (title, content, category, user_id) VALUES (?, ?, ?, ?)',
      [title, content, category, req.user.id]
    );
    res.json({ message: 'Thread created', threadId: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});


// Add a post to a thread (authenticated)
app.post('/threads/:id/posts', authenticateToken, async (req, res) => {
  const threadId = req.params.id;
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Missing content' });

  try {
    const [result] = await pool.query(
      'INSERT INTO posts (thread_id, user_id, content) VALUES (?, ?, ?)',
      [threadId, req.user.id, content]
    );
    res.json({ message: 'Post created', postId: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
