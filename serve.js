const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');
const app = express();
const db = new sqlite3.Database('./users.sqlite');
const SECRET_KEY = 'your-secret-key';
const multer = require('multer');
const fs = require('fs');
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const name = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9-_]/g, '_');
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, `${name}-${unique}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 最大 10MB
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('不支援的檔案格式'));
  }
});
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// JWT 驗證中介層
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) return res.status(401).send('缺少授權');

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).send('Token 無效');
    req.user = user;
    next();
  });
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send('請輸入 Email');

  const newPass = crypto.randomBytes(4).toString('hex'); // 產生 8 碼
  const hashed = bcrypt.hashSync(newPass, 10);

  db.run('UPDATE users SET password = ? WHERE email = ?', [hashed, email], function (err) {
    if (err) return res.status(500).send('伺服器錯誤');
    if (this.changes === 0) return res.status(400).send('查無此 Email');
    res.send(`新密碼為：${newPass}`);
  });
});

app.post('/register', async (req, res) => {
  console.log('收到註冊請求:', req.body); // 加在這裡
  const { username, password, student_id, name, phone, email } = req.body;
  if (!username || !password || !student_id || !name || !phone || !email) {
    return res.status(400).send('請完整填寫所有欄位');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = `INSERT INTO users (username, password, student_id, name, phone, email)
                 VALUES (?, ?, ?, ?, ?, ?)`;

    db.run(sql, [username, hashedPassword, student_id, name, phone, email], function (err) {
      if (err) {
        console.log('註冊錯誤:', err); // 加這一行
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).send('帳號已存在');
        }
        return res.status(500).send('資料庫錯誤');
      }
      res.send('註冊成功，請返回登入');
    });
  } catch (error) {
    console.log('註冊 try/catch 錯誤:', error); // 可選，加強除錯
    res.status(500).send('伺服器錯誤');
  }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).send('伺服器錯誤');
    if (!user) return res.status(400).send('帳號不存在');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).send('密碼錯誤');

    const token = jwt.sign({
      id: user.id,
      username: user.username,
      name: user.name,
    }, SECRET_KEY, { expiresIn: '1d' });

    res.json({ token });
  });
});

app.get('/profile-data', authMiddleware, (req, res) => {
  db.get('SELECT username, student_id, name, phone, email FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err) return res.status(500).send('伺服器錯誤');
    if (!row) return res.status(404).send('找不到使用者資料');
    res.json(row);
  });
});

// 上傳 API（需登入）
app.post('/upload', authMiddleware, upload.single('file'), (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).send('沒有收到檔案');

  const fileUrl = `/uploads/${file.filename}`;
  const isImage = file.mimetype.startsWith('image/');
  const content = isImage ? `<img src="${fileUrl}" style="max-width:100%">`
                          : `<a href="${fileUrl}" target="_blank">下載檔案</a>`;

  const sql = `INSERT INTO messages (user_id, username, category, content, timestamp, is_announcement)
               VALUES (?, ?, ?, ?, datetime('now','localtime'), 0)`;

  db.run(sql, [req.user.id, req.user.username, req.body.category, content], function (err) {
    if (err) return res.status(500).send('檔案訊息儲存失敗');
    res.json({ message: '上傳成功', url: fileUrl });
  });
});

app.post('/update-profile', authMiddleware, (req, res) => {
  const { username, student_id, name, phone, email } = req.body;
  if (!username || !student_id || !name || !phone || !email) {
    return res.status(400).send('請完整填寫所有欄位');
  }

  db.get('SELECT id FROM users WHERE username = ? AND id != ?', [username, req.user.id], (err, existingUser) => {
    if (err) return res.status(500).send('伺服器錯誤');
    if (existingUser) return res.status(400).send('此帳號已被使用');

    const sql = `UPDATE users SET username = ?, student_id = ?, name = ?, phone = ?, email = ? WHERE id = ?`;
    db.run(sql, [username, student_id, name, phone, email, req.user.id], function (err) {
      if (err) return res.status(500).send('更新失敗');
      res.send('更新成功');
    });
  });
});

app.post('/change-password', authMiddleware, async (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;

  if (!oldPassword || !newPassword || !confirmPassword) {
    return res.status(400).send('請填寫所有欄位');
  }
  if (newPassword !== confirmPassword) {
    return res.status(400).send('新密碼與確認密碼不符');
  }

  db.get('SELECT password FROM users WHERE id = ?', [req.user.id], async (err, row) => {
    if (err) return res.status(500).send('伺服器錯誤');
    if (!row) return res.status(400).send('找不到使用者');

    const isMatch = await bcrypt.compare(oldPassword, row.password);
    if (!isMatch) return res.status(400).send('舊密碼錯誤');

    const hashed = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, req.user.id], function (err) {
      if (err) return res.status(500).send('更新密碼失敗');
      res.send('密碼修改成功');
    });
  });
});

app.post('/send', authMiddleware, (req, res) => {
  const { category, content } = req.body;
  if (!category || !content) return res.status(400).send('缺少分類或內容');

  const sql = `INSERT INTO messages (user_id, username, category, content, timestamp)
               VALUES (?, ?, ?, ?, datetime('now','localtime'))`;
  db.run(sql, [req.user.id, req.user.username, category, content], function (err) {
    if (err) return res.status(500).send('儲存訊息失敗');
    res.send('訊息已儲存');
  });
});

app.get('/messages', authMiddleware, (req, res) => {
  const category = req.query.category;
  if (!category) return res.status(400).send('缺少分類');

  const sql = `SELECT username, content, timestamp FROM messages 
               WHERE category = ? ORDER BY timestamp ASC LIMIT 100`;

  db.all(sql, [category], (err, rows) => {
    if (err) return res.status(500).send('無法取得訊息');
    res.json(rows);
  });
});

// 建立社團
app.post('/clubs', authMiddleware, (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).send('請輸入社團名稱');

  const sql = 'INSERT INTO clubs (name, description) VALUES (?, ?)';
  db.run(sql, [name, description || ''], function (err) {
    if (err) return res.status(500).send('建立失敗，可能社團已存在');

    // 建立者為社長
    db.run('INSERT INTO club_members (user_id, club_id, role, approved) VALUES (?, ?, ?, 1)',
      [req.user.id, this.lastID, 'president'],
      (err) => {
        if (err) return res.status(500).send('社長建立失敗');
        res.send('社團建立成功');
      });
  });
});

// 加入社團申請
app.post('/join-club', authMiddleware, (req, res) => {
  const { club_id } = req.body;
  if (!club_id) return res.status(400).send('請選擇社團');

  db.get('SELECT * FROM club_members WHERE user_id = ? AND club_id = ?', [req.user.id, club_id], (err, row) => {
    if (row) return res.status(400).send('你已申請或是成員');

    db.run('INSERT INTO club_members (user_id, club_id, role, approved) VALUES (?, ?, ?, 0)',
      [req.user.id, club_id, 'member'],
      (err) => {
        if (err) return res.status(500).send('申請失敗');
        res.send('已送出加入申請');
      });
  });
});

// 取得所有社團（給前端列表用）
app.get('/clubs', (req, res) => {
  db.all('SELECT * FROM clubs', [], (err, rows) => {
    if (err) return res.status(500).send('取得社團失敗');
    res.json(rows);
  });
});

// 取得該社長所管理社團的申請列表
app.get('/club-applicants/:club_id', authMiddleware, (req, res) => {
  const club_id = req.params.club_id;

  db.get('SELECT * FROM club_members WHERE user_id = ? AND club_id = ? AND role IN ("president", "officer") AND approved = 1',
    [req.user.id, club_id], (err, roleRow) => {
      if (!roleRow) return res.status(403).send('你沒有審核權限');

      const sql = `SELECT u.id, u.name, u.username FROM users u
                   JOIN club_members cm ON u.id = cm.user_id
                   WHERE cm.club_id = ? AND cm.approved = 0`;
      db.all(sql, [club_id], (err, rows) => {
        if (err) return res.status(500).send('無法取得申請者');
        res.json(rows);
      });
    });
});

// 核准成員加入社團
app.post('/approve-member', authMiddleware, (req, res) => {
  const { club_id, user_id } = req.body;

  db.get('SELECT * FROM club_members WHERE user_id = ? AND club_id = ? AND role IN ("president", "officer") AND approved = 1',
    [req.user.id, club_id], (err, row) => {
      if (!row) return res.status(403).send('你沒有核准權限');

      db.run('UPDATE club_members SET approved = 1 WHERE user_id = ? AND club_id = ?',
        [user_id, club_id],
        (err) => {
          if (err) return res.status(500).send('更新失敗');
          res.send('已核准');
        });
    });
});

// 取得自己所屬社團
app.get('/my-clubs', authMiddleware, (req, res) => {
  const sql = `SELECT c.id, c.name, cm.role FROM clubs c
               JOIN club_members cm ON c.id = cm.club_id
               WHERE cm.user_id = ? AND cm.approved = 1`;
  db.all(sql, [req.user.id], (err, rows) => {
    if (err) return res.status(500).send('無法取得社團');
    res.json(rows);
  });
});

// ✅ /send 路由，支援公告權限驗證
app.post('/send', authMiddleware, (req, res) => {
  const { category, content, is_announcement } = req.body;
  if (!category || !content) return res.status(400).send('缺少分類或內容');

  let isAnnounce = parseInt(is_announcement) === 1 || is_announcement === true;

  // 如果不是公告，直接存入
  if (!isAnnounce) {
    const sql = `INSERT INTO messages (user_id, username, category, content, timestamp, is_announcement)
                 VALUES (?, ?, ?, ?, datetime('now','localtime'), 0)`;
    db.run(sql, [req.user.id, req.user.username, category, content], function (err) {
      if (err) return res.status(500).send('儲存訊息失敗');
      res.send('訊息已儲存');
    });
  } else {
    // 驗證是否為社長或幹部
    const match = category.match(/^club-(\d+)$/);
    if (!match) return res.status(403).send('只有社團聊天室才能發布公告');
    const club_id = parseInt(match[1]);

    db.get('SELECT * FROM club_members WHERE user_id = ? AND club_id = ? AND role IN ("president", "officer") AND approved = 1',
      [req.user.id, club_id], (err, row) => {
        if (err) return res.status(500).send('權限查詢錯誤');
        if (!row) return res.status(403).send('你不是幹部/社長，無法發布公告');

        const sql = `INSERT INTO messages (user_id, username, category, content, timestamp, is_announcement)
                     VALUES (?, ?, ?, ?, datetime('now','localtime'), 1)`;
        db.run(sql, [req.user.id, req.user.username, category, content], function (err) {
          if (err) return res.status(500).send('儲存公告失敗');
          res.send('公告已發布');
        });
      });
  }
});

// ✅ /messages 路由：取得一般訊息（非公告）
app.get('/messages', authMiddleware, (req, res) => {
  const category = req.query.category;
  if (!category) return res.status(400).send('缺少分類');

  const sql = `SELECT id, username, content, timestamp, is_announcement FROM messages 
               WHERE category = ? AND is_announcement = 0 
               ORDER BY timestamp ASC LIMIT 100`;

  db.all(sql, [category], (err, rows) => {
    if (err) return res.status(500).send('無法取得訊息');
    res.json(rows);
  });
});

// ✅ /messages/announcements 路由：取得公告訊息
app.get('/messages/announcements', authMiddleware, (req, res) => {
  const category = req.query.category;
  if (!category) return res.status(400).send('缺少分類');

  const sql = `SELECT id, username, content, timestamp, is_announcement FROM messages 
               WHERE category = ? AND is_announcement = 1 
               ORDER BY timestamp DESC LIMIT 100`;

  db.all(sql, [category], (err, rows) => {
    if (err) return res.status(500).send('無法取得公告');
    res.json(rows);
  });
});

// ✅ 更新公告內容
app.post('/messages/update-announcement', authMiddleware, (req, res) => {
  const { id, content } = req.body;
  if (!id || !content) return res.status(400).send('缺少內容或 ID');

  const sql = `UPDATE messages SET content = ? WHERE id = ? AND is_announcement = 1 AND user_id = ?`;
  db.run(sql, [content, id, req.user.id], function (err) {
    if (err || this.changes === 0) return res.status(403).send('更新失敗或無權限');
    res.send('更新成功');
  });
});

// ✅ 刪除公告
app.post('/messages/delete-announcement', authMiddleware, (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).send('缺少公告 ID');

  const sql = `DELETE FROM messages WHERE id = ? AND is_announcement = 1 AND user_id = ?`;
  db.run(sql, [id, req.user.id], function (err) {
    if (err || this.changes === 0) return res.status(403).send('刪除失敗或無權限');
    res.send('已刪除公告');
  });
});


app.listen(3000, () => {
  console.log('伺服器啟動：http://localhost:3000');
});

