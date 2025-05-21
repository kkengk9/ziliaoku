const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./users.sqlite');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));


app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
}));

// 根路由導向登入頁
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// 註冊頁面 (可直接用靜態檔案，也可以用此路由)
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// 註冊 API
app.post('/register', async (req, res) => {
  const { username, password, student_id, name, phone, email } = req.body;

  if (!username || !password || !student_id || !name || !phone || !email) {
    return res.status(400).send('請完整填寫所有欄位');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO users (username, password, student_id, name, phone, email)
                 VALUES (?, ?, ?, ?, ?, ?)`;

    db.run(sql, [username, hashedPassword, student_id, name, phone, email], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).send('帳號已存在');
        }
        return res.status(500).send('資料庫錯誤');
      }
      res.send('註冊成功，請返回登入');
    });
  } catch (error) {
    res.status(500).send('伺服器錯誤');
  }
});

// 登入 API
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).send('伺服器錯誤');
    if (!user) return res.status(400).send('帳號不存在');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).send('密碼錯誤');

    req.session.user = {
      id: user.id,
      username: user.username,
      name: user.name,
    };

    res.send('登入成功');
  });
});

// 登出 API
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.send('已登出');
});

// 保護頁面 - profile，登入後兩秒跳轉聊天室
app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('尚未登入');
  }
  res.send(`
    <h2>歡迎回來, ${req.session.user.name}</h2>
    <p>兩秒後將跳轉至聊天室...</p>
    <a href="/change-password.html">修改密碼</a>
    <script>
      setTimeout(() => {
        window.location.href = '/chat.html';
      }, 2000);
    </script>
  `);
});

// 修改密碼 API
app.post('/change-password', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('尚未登入');
  }

  const userId = req.session.user.id;
  const { oldPassword, newPassword, confirmPassword } = req.body;

  if (!oldPassword || !newPassword || !confirmPassword) {
    return res.status(400).send('請填寫所有欄位');
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).send('新密碼與確認密碼不符');
  }

  db.get('SELECT password FROM users WHERE id = ?', [userId], async (err, row) => {
    if (err) return res.status(500).send('伺服器錯誤');
    if (!row) return res.status(400).send('找不到使用者');

    const isMatch = await bcrypt.compare(oldPassword, row.password);
    if (!isMatch) return res.status(400).send('舊密碼錯誤');

    const hashed = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, userId], function(err) {
      if (err) return res.status(500).send('更新密碼失敗');
      res.send('密碼修改成功');
    });
  });
});

app.listen(3000, () => {
  console.log('伺服器啟動：http://localhost:3000');
});
// 確保這行在 require 區塊之後
const { promisify } = require('util');

// 加入 /send 路由：發送訊息
app.post('/send', (req, res) => {
    console.log('session user:', req.session.user);

  if (!req.session.user) {
    return res.status(401).send('尚未登入');
  }
  const { category, content } = req.body;
  if (!category || !content) {
    return res.status(400).send('缺少分類或內容');
  }

  const sql = `INSERT INTO messages (user_id, username, category, content, timestamp)
               VALUES (?, ?, ?, ?, datetime('now','localtime'))`;
  db.run(sql, [req.session.user.id, req.session.user.username, category, content], function(err) {
    if (err) {
      console.error('儲存訊息錯誤:', err.message);
      return res.status(500).send('儲存訊息失敗');
    }
    res.send('訊息已儲存');
  });
});

// 加入 /messages 路由：取得訊息列表，依分類撈取
app.get('/messages', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('尚未登入');
  }
  const category = req.query.category;
  if (!category) return res.status(400).send('缺少分類');

  const sql = `SELECT username, content, timestamp FROM messages 
               WHERE category = ? ORDER BY timestamp ASC LIMIT 100`;

  db.all(sql, [category], (err, rows) => {
    if (err) return res.status(500).send('無法取得訊息');
    res.json(rows);
  });
});
// 取得目前使用者資料（給前端填表用）
app.get('/profile-data', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('尚未登入');
  }

  db.get('SELECT username, student_id, name, phone, email FROM users WHERE id = ?', [req.session.user.id], (err, row) => {
    if (err) return res.status(500).send('伺服器錯誤');
    if (!row) return res.status(404).send('找不到使用者資料');
    res.json(row);
  });
});

// 更新個人資訊
app.post('/update-profile', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('尚未登入');
  }

  const userId = req.session.user.id;
  const { username, student_id, name, phone, email } = req.body;

  if (!username || !student_id || !name || !phone || !email) {
    return res.status(400).send('請完整填寫所有欄位');
  }

  // 注意：這邊要避免使用者更新為已存在的 username
  db.get('SELECT id FROM users WHERE username = ? AND id != ?', [username, userId], (err, existingUser) => {
    if (err) return res.status(500).send('伺服器錯誤');
    if (existingUser) return res.status(400).send('此帳號已被使用');

    const sql = `UPDATE users SET username = ?, student_id = ?, name = ?, phone = ?, email = ? WHERE id = ?`;
    db.run(sql, [username, student_id, name, phone, email, userId], function(err) {
      if (err) return res.status(500).send('更新失敗');
      // 同步更新 session 的 username 和 name
      req.session.user.username = username;
      req.session.user.name = name;
      res.send('更新成功');
    });
  });
});
