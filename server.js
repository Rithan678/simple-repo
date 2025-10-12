const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Database setup
const db = new sqlite3.Database('./database.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database');
    // Create users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Create posts table for CRUD operations
    db.run(`CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      user_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
  }
});

// Middleware
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: 'your-secret-key-here',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.render('login', { error: 'Database error' });
    }
    
    if (user && await bcrypt.compare(password, user.password)) {
      req.session.user = { id: user.id, username: user.username };
      res.redirect('/dashboard');
    } else {
      res.render('login', { error: 'Invalid credentials' });
    }
  });
});

app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
           [username, email, hashedPassword], function(err) {
      if (err) {
        return res.render('register', { error: 'Username or email already exists' });
      }
      
      req.session.user = { id: this.lastID, username };
      res.redirect('/dashboard');
    });
  } catch (error) {
    res.render('register', { error: 'Registration failed' });
  }
});

app.get('/dashboard', requireAuth, (req, res) => {
  db.all('SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC', 
         [req.session.user.id], (err, posts) => {
    if (err) {
      console.error(err);
      posts = [];
    }
    res.render('dashboard', { user: req.session.user, posts });
  });
});

app.get('/posts/new', requireAuth, (req, res) => {
  res.render('new-post', { user: req.session.user });
});

app.post('/posts', requireAuth, (req, res) => {
  const { title, content } = req.body;
  
  db.run('INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)',
         [title, content, req.session.user.id], (err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/dashboard');
  });
});

app.get('/posts/:id/edit', requireAuth, (req, res) => {
  const postId = req.params.id;
  
  db.get('SELECT * FROM posts WHERE id = ? AND user_id = ?', 
         [postId, req.session.user.id], (err, post) => {
    if (err || !post) {
      return res.redirect('/dashboard');
    }
    res.render('edit-post', { user: req.session.user, post });
  });
});

app.post('/posts/:id', requireAuth, (req, res) => {
  const { title, content } = req.body;
  const postId = req.params.id;
  
  db.run('UPDATE posts SET title = ?, content = ? WHERE id = ? AND user_id = ?',
         [title, content, postId, req.session.user.id], (err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/dashboard');
  });
});

app.post('/posts/:id/delete', requireAuth, (req, res) => {
  const postId = req.params.id;
  
  db.run('DELETE FROM posts WHERE id = ? AND user_id = ?',
         [postId, req.session.user.id], (err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/dashboard');
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});