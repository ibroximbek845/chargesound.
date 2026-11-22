const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

if (!process.env.DATABASE_URL || !JWT_SECRET || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.error('Missing DATABASE_URL, JWT_SECRET, ADMIN_EMAIL or ADMIN_PASSWORD environment variable.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false });
const orderLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 15, standardHeaders: true, legacyHeaders: false });

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name VARCHAR(140) NOT NULL,
      category VARCHAR(50) NOT NULL DEFAULT 'New arrivals',
      description TEXT NOT NULL DEFAULT '',
      price NUMERIC(12,2) NOT NULL CHECK (price >= 0),
      image_url TEXT NOT NULL DEFAULT '',
      sizes TEXT[] NOT NULL DEFAULT ARRAY['S','M','L'],
      featured BOOLEAN NOT NULL DEFAULT false,
      active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      customer_name VARCHAR(120) NOT NULL,
      phone VARCHAR(40) NOT NULL,
      address TEXT NOT NULL,
      items JSONB NOT NULL,
      total NUMERIC(12,2) NOT NULL,
      status VARCHAR(30) NOT NULL DEFAULT 'new',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  const count = await pool.query('SELECT COUNT(*)::int AS count FROM products');
  if (count.rows[0].count === 0) {
    await pool.query(
      `INSERT INTO products (name,category,description,price,image_url,sizes,featured) VALUES
      ($1,$2,$3,$4,$5,$6,$7),($8,$9,$10,$11,$12,$13,$14),($15,$16,$17,$18,$19,$20,$21),($22,$23,$24,$25,$26,$27,$28)`,
      [
        'The Sculpted Blazer','Women','A refined silhouette, tailored for a timeless wardrobe.',189,'https://images.unsplash.com/photo-1591047139829-d91aecb6caea?auto=format&fit=crop&w=900&q=85',['XS','S','M','L'],true,
        'Essential Wool Coat','Women','Soft structure and understated elegance for colder days.',249,'https://images.unsplash.com/photo-1539533018447-63fcce2678e3?auto=format&fit=crop&w=900&q=85',['S','M','L'],true,
        'Modern Tailored Shirt','Men','An elevated everyday essential in premium cotton.',89,'https://images.unsplash.com/photo-1603252109303-2751441dd157?auto=format&fit=crop&w=900&q=85',['S','M','L','XL'],false,
        'Leather Weekend Bag','Accessories','A minimal companion for work and travel.',159,'https://images.unsplash.com/photo-1553062407-98eeb64c6a62?auto=format&fit=crop&w=900&q=85',['One size'],false
      ]
    );
  }
}

function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.cookies?.token;
  if (!token) return res.status(401).json({ error: 'Sign in required.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'admin' || payload.email !== ADMIN_EMAIL) throw new Error('Invalid role');
    req.admin = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired. Sign in again.' });
  }
}

app.post('/api/admin/login', loginLimiter, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Email or password is incorrect.' });
  }
  const token = jwt.sign({ email, role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, email, expiresIn: 28800 });
});

app.get('/api/products', async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      'SELECT id,name,category,description,price,image_url,sizes,featured FROM products WHERE active=true ORDER BY featured DESC, created_at DESC'
    );
    res.json(rows);
  } catch (e) { next(e); }
});

app.post('/api/orders', orderLimiter, async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim().slice(0,120);
    const phone = String(req.body.phone || '').trim().slice(0,40);
    const address = String(req.body.address || '').trim().slice(0,500);
    const cart = Array.isArray(req.body.items) ? req.body.items : [];
    if (!name || !phone || !address || !cart.length || cart.length > 20) {
      return res.status(400).json({ error: 'Please complete all details and add an item.' });
    }
    const ids = [...new Set(cart.map(x => Number(x.id)).filter(Number.isInteger))];
    const { rows: products } = await pool.query(
      'SELECT id,name,price FROM products WHERE active=true AND id=ANY($1::int[])', [ids]
    );
    const byId = new Map(products.map(p => [p.id, p]));
    const items = [];
    let total = 0;
    for (const line of cart) {
      const product = byId.get(Number(line.id));
      const qty = Math.max(1, Math.min(10, Number(line.quantity) || 1));
      if (!product) continue;
      const lineTotal = Number(product.price) * qty;
      total += lineTotal;
      items.push({ id: product.id, name: product.name, price: Number(product.price), quantity: qty, size: String(line.size || '').slice(0,12) });
    }
    if (!items.length) return res.status(400).json({ error: 'Your cart is no longer available. Refresh and try again.' });
    const result = await pool.query(
      'INSERT INTO orders(customer_name,phone,address,items,total) VALUES($1,$2,$3,$4,$5) RETURNING id',
      [name, phone, address, JSON.stringify(items), total.toFixed(2)]
    );
    res.status(201).json({ message: 'Your order has been received.', orderId: result.rows[0].id });
  } catch (e) { next(e); }
});

app.get('/api/admin/me', requireAdmin, (req,res) => res.json({ email: req.admin.email, role: 'admin' }));

app.get('/api/admin/products', requireAdmin, async (req,res,next) => {
  try { const { rows } = await pool.query('SELECT * FROM products ORDER BY created_at DESC'); res.json(rows); }
  catch(e) { next(e); }
});

app.post('/api/admin/products', requireAdmin, async (req,res,next) => {
  try {
    const p = req.body;
    if (!String(p.name || '').trim() || !Number.isFinite(Number(p.price)) || Number(p.price) < 0) return res.status(400).json({error:'Name and valid price are required.'});
    const { rows } = await pool.query(
      'INSERT INTO products(name,category,description,price,image_url,sizes,featured,active) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [String(p.name).trim().slice(0,140),String(p.category||'New arrivals').slice(0,50),String(p.description||'').slice(0,2000),Number(p.price),String(p.image_url||'').slice(0,1500),Array.isArray(p.sizes)?p.sizes.map(String).slice(0,8):['S','M','L'],!!p.featured,p.active!==false]
    );
    res.status(201).json(rows[0]);
  } catch(e) { next(e); }
});

app.put('/api/admin/products/:id', requireAdmin, async (req,res,next) => {
  try {
    const p=req.body;
    const { rows }=await pool.query(
      'UPDATE products SET name=$1,category=$2,description=$3,price=$4,image_url=$5,sizes=$6,featured=$7,active=$8 WHERE id=$9 RETURNING *',
      [String(p.name||'').trim().slice(0,140),String(p.category||'New arrivals').slice(0,50),String(p.description||'').slice(0,2000),Math.max(0,Number(p.price)||0),String(p.image_url||'').slice(0,1500),Array.isArray(p.sizes)?p.sizes.map(String).slice(0,8):['S','M','L'],!!p.featured,p.active!==false,Number(req.params.id)]
    );
    if(!rows.length) return res.status(404).json({error:'Product not found.'});
    res.json(rows[0]);
  } catch(e) { next(e); }
});

app.delete('/api/admin/products/:id', requireAdmin, async (req,res,next) => {
  try { await pool.query('UPDATE products SET active=false WHERE id=$1',[Number(req.params.id)]); res.json({ok:true}); }
  catch(e) { next(e); }
});

app.get('/api/admin/orders', requireAdmin, async (req,res,next) => {
  try { const { rows }=await pool.query('SELECT * FROM orders ORDER BY created_at DESC LIMIT 200'); res.json(rows); }
  catch(e) { next(e); }
});

app.patch('/api/admin/orders/:id', requireAdmin, async (req,res,next) => {
  try {
    const allowed=['new','confirmed','shipped','completed','cancelled'];
    if(!allowed.includes(req.body.status)) return res.status(400).json({error:'Invalid status.'});
    const { rows }=await pool.query('UPDATE orders SET status=$1 WHERE id=$2 RETURNING *',[req.body.status,Number(req.params.id)]);
    if(!rows.length) return res.status(404).json({error:'Order not found.'});
    res.json(rows[0]);
  } catch(e) { next(e); }
});

app.get('/admin', (req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));
app.get('*', (req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

app.use((err,req,res,next)=>{
  console.error(err);
  res.status(500).json({error:'Something went wrong. Please try again.'});
});

initDb().then(()=>{
  app.listen(PORT,'0.0.0.0',()=>console.log('Luxury Fashion running on port '+PORT));
}).catch(err=>{ console.error('Database initialization failed:',err); process.exit(1); });
