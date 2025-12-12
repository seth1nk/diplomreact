import express from 'express';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import axios from 'axios';
import { fileURLToPath } from 'url';

// Если файла data.js нет, закомментируй строку ниже
import { seedDatabase } from './data.js';

const { Pool } = pg;

// --- НАСТРОЙКИ ДЛЯ МОДУЛЕЙ ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// --- ВАЖНО: ПОЛУЧАЕМ ПОРТ ОТ ПАНЕЛИ ---
const args = process.argv.slice(2);
const portArgIndex = args.indexOf('--port');
const PORT = portArgIndex !== -1 ? parseInt(args[portArgIndex + 1]) : 5000;

app.use((req, res, next) => {
    // Разрешает всплывающее окно Google
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
    // Разрешает загрузку ресурсов
    res.setHeader("Cross-Origin-Embedder-Policy", "unsafe-none");
    // Исправляет проблемы с редиректами
    res.setHeader("Referrer-Policy", "no-referrer-when-downgrade");
    next();
});

// === MIDDLEWARE ===
app.use(cors()); // Разрешаем CORS
app.use(express.json());

// === СТАТИКА (ФАЙЛЫ) ===
// 1. Папка для загруженных картинок
if (!fs.existsSync('Uploads')) fs.mkdirSync('Uploads');
app.use('/Uploads', express.static(path.join(__dirname, 'Uploads')));

// 2. Раздача REACT (папка dist)
app.use(express.static(path.join(__dirname, 'dist')));

// Настройка загрузчика файлов
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'Uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

// === КОНФИГУРАЦИЯ ===
const SECRET_KEY = 'smart-nexus-secret-key-hardcore';
const BOT_TOKEN = "7994786340:AAETOxVf_FvhTpI-FD4WrzellOV59npDyoU"; 
const TG_ADMIN_ID = 1163547353; 

// === ПОДКЛЮЧЕНИЕ К БАЗЕ ДАННЫХ ===
const pool = new Pool({
  user: 'test',
  host: '127.0.0.1',
  database: 'test_db',
  password: 'bc7A2C891a',
  port: 5432,
});

// --- УТИЛИТЫ ---
async function sendTelegramMessage(chatId, text, keyboard = null) {
  if (!chatId) {
    console.log('[TG] Ошибка: нет Chat ID');
    return;
  }
  try {
    const body = {
      chat_id: chatId,
      text: text,
      parse_mode: 'HTML' 
    };
    if (keyboard) {
      body.reply_markup = keyboard;
    }
    await axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, body);
    console.log(`[TG] ✅ Успешно отправлено юзеру ${chatId}`);
  } catch (e) {
    console.error('[TG] ❌ Ошибка API:', e.response ? e.response.data : e.message);
  }
}

// --- INIT ---
(async () => {
  const client = await pool.connect();
  try {
    // Твои запросы к БД (оставил как было)
    // await client.query('DROP TABLE IF EXISTS messages CASCADE');
    
    await client.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE, password VARCHAR(255), name VARCHAR(255), picture VARCHAR(255), role VARCHAR(50) DEFAULT 'user', phone VARCHAR(50), status VARCHAR(50) DEFAULT 'active', last_login TIMESTAMP, ip VARCHAR(50), referral_code VARCHAR(100), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await client.query(`CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, name VARCHAR(255), description TEXT, price DECIMAL(10,2), image VARCHAR(255), category VARCHAR(100) DEFAULT 'General', stock INTEGER DEFAULT 0, rating DECIMAL(2,1) DEFAULT 5.0, sku VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await client.query(`CREATE TABLE IF NOT EXISTS orders (id SERIAL PRIMARY KEY, user_id INTEGER, order_number INTEGER, status VARCHAR(50) DEFAULT 'placed', payment_status VARCHAR(50) DEFAULT 'pending', total DECIMAL(10,2), content TEXT, payment_method VARCHAR(50), delivery_address TEXT, tracking VARCHAR(100), telegram_chat_id BIGINT, telegram_username VARCHAR(255), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await client.query(`CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, user_name VARCHAR(255), email VARCHAR(255), text TEXT, subject VARCHAR(255) DEFAULT 'Chat', is_admin BOOLEAN DEFAULT FALSE, is_read BOOLEAN DEFAULT FALSE, ip VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await client.query(`CREATE TABLE IF NOT EXISTS logs (id SERIAL PRIMARY KEY, user_id INTEGER, username VARCHAR(255), method VARCHAR(10), url VARCHAR(255), action TEXT, ip VARCHAR(50), status_code INTEGER, details TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    
    // await seedDatabase(pool); 
  } catch(e) { console.error(e); } finally { client.release(); }
})();

// --- MIDDLEWARE LOGGING ---
app.use((req, res, next) => {
  if (req.url.startsWith('/Uploads') || req.method === 'OPTIONS') return next();
  const start = Date.now();
  res.on('finish', async () => {
    // Не логируем запросы к статике React (js, css, etc)
    if (!req.url.match(/\.(js|css|png|jpg|ico|woff2)$/)) {
        const duration = Date.now() - start;
        let username = 'Guest'; let uid = null;
        if (req.headers['authorization']) {
            try {
                const token = req.headers['authorization'].split(' ')[1];
                const d = jwt.verify(token, SECRET_KEY);
                username = d.name; uid = d.id;
            } catch(e){}
        }
        try {
            const details = JSON.stringify(req.body || {}).slice(0, 100);
            await pool.query(`INSERT INTO logs (user_id, username, method, url, action, ip, status_code, details, timestamp) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
                [uid, username, req.method, req.url, `Time: ${duration}ms`, req.ip, res.statusCode, details]);
        } catch (e) {}
    }
  });
  next();
});

const auth = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({message: 'No token'});
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({message: 'Invalid token'});
    req.user = user; next();
  });
};

const checkAdmin = async (req, res, next) => {
  const result = await pool.query('SELECT role FROM users WHERE id = $1', [req.user.id]);
  if (result.rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
};

// ================= ROUTES =================

app.post('/register', async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.password, 10);
    const result = await pool.query('INSERT INTO users (email, password, name, role, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING *', [req.body.email, hash, req.body.name, 'user']);
    const token = jwt.sign({ id: result.rows[0].id, name: req.body.name }, SECRET_KEY);
    res.json({ token, user: result.rows[0] });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/login', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM users WHERE email = $1', [req.body.email]);
    if (!r.rows.length) return res.status(400).json({ error: 'Not found' });
    if (!await bcrypt.compare(req.body.password, r.rows[0].password)) return res.status(400).json({ error: 'Wrong pass' });
    const token = jwt.sign({ id: r.rows[0].id, name: r.rows[0].name }, SECRET_KEY);
    res.json({ token, user: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/orders', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM orders WHERE user_id = $1 ORDER BY id DESC', [req.user.id]);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/orders', auth, async (req, res) => {
  const { cart, delivery } = req.body;
  const total = cart.reduce((a,c) => a + c.price * c.qty, 0);
  const content = cart.map(i => `${i.name} (x${i.qty})`).join(', ');
  const orderNum = Math.floor(100000 + Math.random() * 900000);
  let dInfo = delivery ? `Адрес: ${delivery.address}\n👤 ${delivery.fio}\n📞 ${delivery.phone}\n📅 ${delivery.date}` : 'Не указан';
  try {
    const result = await pool.query(`INSERT INTO orders (user_id, order_number, total, content, status, delivery_address, payment_status, created_at) VALUES ($1, $2, $3, $4, 'placed', $5, 'pending', NOW()) RETURNING id`, [req.user.id, orderNum, total, content, dInfo]);
    res.json({ success: true, orderId: result.rows[0].id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/orders', auth, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT role, name, email FROM users WHERE id = $1', [req.user.id]);
    const u = userRes.rows[0];
    const r = await pool.query(`
        SELECT o.*, u.name as username, u.email as user_email 
        FROM orders o 
        LEFT JOIN users u ON o.user_id = u.id 
        ORDER BY o.id DESC
    `);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/admin/orders/:id', auth, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT role, name, email FROM users WHERE id = $1', [req.user.id]);
    const u = userRes.rows[0];
    const isAdmin = u.role === 'admin' || u.name === 'seth1nk' || u.email === 'admin@mail.ru';

    if (!isAdmin) return res.status(403).json({ error: 'Access denied' });

    const { status } = req.body;
    await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [status, req.params.id]);

    const orderRes = await pool.query('SELECT order_number, telegram_chat_id, telegram_username FROM orders WHERE id = $1', [req.params.id]);
    const order = orderRes.rows[0];
    
    if (order && order.telegram_chat_id) {
        let msg = `📦 <b>Заказ #${order.order_number} обновлен!</b>\nСтатус: ${status}`;
        await sendTelegramMessage(order.telegram_chat_id, msg);
    }

    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/messages', auth, async (req, res) => { 
  try {
    const userRes = await pool.query('SELECT role, name, email FROM users WHERE id = $1', [req.user.id]);
    const u = userRes.rows[0];
    const isAdmin = u.role === 'admin' || u.name === 'seth1nk' || u.email === 'admin@mail.ru';
    if (isAdmin) {
        const r = await pool.query('SELECT * FROM messages ORDER BY created_at ASC');
        res.json(r.rows);
    } else {
        const r = await pool.query('SELECT * FROM messages WHERE email = $1 ORDER BY created_at ASC', [u.email]);
        res.json(r.rows);
    }
  } catch(e) { res.status(500).json({error: e.message}); }
});

app.get('/admin/messages', auth, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const u = userRes.rows[0];
    const r = await pool.query('SELECT * FROM messages ORDER BY created_at DESC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/messages/unread', auth, async (req, res) => {
    try {
        const r = await pool.query("SELECT COUNT(*) FROM messages WHERE is_admin = TRUE AND is_read = FALSE");
        res.json({ count: parseInt(r.rows[0].count) });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/logs', auth, async (req, res) => { 
    const r = await pool.query('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100'); 
    res.json(r.rows); 
});

app.get('/products', async (req, res) => { const r = await pool.query('SELECT * FROM products ORDER BY id ASC'); res.json(r.rows); });

app.post('/admin/products', auth, checkAdmin, upload.single('image'), async (req, res) => {
    const img = req.file ? `Uploads/${req.file.filename}` : '';
    await pool.query('INSERT INTO products (name, description, price, image, category, created_at) VALUES ($1, $2, $3, $4, $5, NOW())', [req.body.name, req.body.description, req.body.price, img, req.body.category]);
    res.json({ success: true });
});

app.put('/admin/products/:id', auth, checkAdmin, async (req, res) => { await pool.query('UPDATE products SET name=$1, price=$2, description=$3, category=$4 WHERE id=$5', [req.body.name, req.body.price, req.body.description, req.body.category, req.params.id]); res.json({ success: true }); });

app.delete('/admin/products/:id', auth, checkAdmin, async (req, res) => { await pool.query('DELETE FROM products WHERE id = $1', [req.params.id]); res.json({ success: true }); });

app.put('/users/password', auth, async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hash, req.user.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/users', auth, async (req, res) => { 
  const r = await pool.query('SELECT * FROM users ORDER BY id ASC'); 
  res.json(r.rows); 
});

app.post('/admin/users', auth, checkAdmin, async (req, res) => {
    const hash = await bcrypt.hash(req.body.password, 10);
    const r = await pool.query("INSERT INTO users (name, email, password, role, status, created_at) VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *", [req.body.name, req.body.email, hash, req.body.role, req.body.status]);
    res.json(r.rows[0]);
});

app.put('/admin/users/:id', auth, checkAdmin, async (req, res) => {
    await pool.query("UPDATE users SET name=$1, email=$2, role=$3, status=$4 WHERE id=$5", [req.body.name, req.body.email, req.body.role, req.body.status, req.params.id]);
    res.json({ success: true });
});

app.delete('/admin/users/:id', auth, checkAdmin, async (req, res) => {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ success: true });
});

app.post('/contact', async (req, res) => {
  try {
    const r = await pool.query('INSERT INTO messages (user_name, email, text, subject, is_admin, is_read, ip, created_at) VALUES ($1, $2, $3, $4, FALSE, FALSE, $5, NOW()) RETURNING *', [req.body.name, req.body.email, req.body.message, 'Chat', req.ip]);
    const kb = { inline_keyboard: [[{ text: "↩️ Ответить", callback_data: `reply_to_${req.body.email}` }]] };
    await sendTelegramMessage(TG_ADMIN_ID, `📩 <b>ЧАТ:</b> ${req.body.name}\n${req.body.message}`, kb);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({error: e.message}); }
});

app.post('/messages/read', auth, async (req, res) => {
    await pool.query("UPDATE messages SET is_read = TRUE WHERE email = $1 AND is_admin = TRUE", [req.body.email]);
    res.json({ success: true });
});

// --- ВНУТРЕННИЕ API ДЛЯ БОТА ---
app.post('/api/internal/orders/link-telegram', async (req, res) => {
  try {
    await pool.query('UPDATE orders SET telegram_chat_id = $1, telegram_username = $2 WHERE id = $3', [req.body.telegramId, req.body.username || 'NoNick', req.body.orderId]);
    const r = await pool.query(`SELECT o.*, o.content as subject, u.email FROM orders o JOIN users u ON o.user_id = u.id WHERE o.id = $1`, [req.body.orderId]);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({error: e.message}); }
});

app.post('/api/internal/orders/:id/confirm-payment', async (req, res) => {
  await pool.query("UPDATE orders SET payment_status = 'paid' WHERE id = $1", [req.params.id]);
  res.json({ success: true });
});

app.get('/api/internal/orders/by-telegram/:tgId', async (req, res) => {
  const r = await pool.query(`SELECT *, content as subject FROM orders WHERE telegram_chat_id = $1 ORDER BY id DESC LIMIT 20`, [req.params.tgId]);
  res.json(r.rows);
});

app.get('/api/internal/orders/detail/:orderId', async (req, res) => {
  const r = await pool.query(`SELECT o.*, o.content as subject, u.email FROM orders o JOIN users u ON o.user_id = u.id WHERE o.id = $1`, [req.params.orderId]);
  res.json(r.rows[0]);
});

app.post('/api/internal/orders/:id/cancel-by-user', async (req, res) => {
    await pool.query("UPDATE orders SET status = 'cancelled' WHERE id = $1", [req.params.id]);
    await sendTelegramMessage(TG_ADMIN_ID, `❌ Клиент отменил заказ #${req.params.id}`);
    res.json({ success: true });
});

app.post('/api/bot/reply', async (req, res) => {
    await pool.query('INSERT INTO messages (user_name, email, text, subject, is_admin, is_read, created_at) VALUES ($1, $2, $3, $4, TRUE, FALSE, NOW())', ['Поддержка', req.body.email, req.body.text, 'Reply']);
    res.json({ success: true });
});

app.post('/api/internal/orders/:id/internal-status', async (req, res) => {
  await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [req.body.status, req.params.id]);
  res.json({ success: true });
});

app.get('/api/internal/orders/admin/all', async (req, res) => {
  const r = await pool.query(`SELECT *, content as subject FROM orders ORDER BY id DESC LIMIT 20`);
  res.json(r.rows);
});

app.post('/auth/google', async (req, res) => {
  try {
    const { access_token } = req.body;
    const googleRes = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', { headers: { Authorization: `Bearer ${access_token}` } });
    const { email, name, picture } = googleRes.data;
    let user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    let userId;
    if (user.rows.length === 0) {
      const newUser = await pool.query('INSERT INTO users (email, name, picture, referral_code, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING *', [email, name, picture, uuidv4()]);
      userId = newUser.rows[0].id; user = newUser;
    } else userId = user.rows[0].id;
    const token = jwt.sign({ id: userId, name: user.rows[0].name }, SECRET_KEY);
    res.json({ token, user: user.rows[0] });
  } catch (e) { res.status(500).json({ error: 'Google Auth Failed' }); }
});

// --- CATCH ALL FOR REACT ---
// Все, что не API, отправляем на index.html
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

// --- START SERVER ---
app.listen(PORT, '0.0.0.0', () => {
    console.log(`SERVER RUNNING ON PORT ${PORT} | PANEL MODE`);
});
