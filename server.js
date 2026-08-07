require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { Resend } = require('resend');
const rateLimit = require('express-rate-limit');
const { Readable } = require('stream');
const fs = require('fs');
const path = require('path');

const app = express();
// Render (and most hosts) sit behind a reverse proxy that terminates HTTPS and
// forwards plain HTTP internally. Without this, req.protocol always reports
// 'http' even on a live https:// site — any URL we build from it (like local
// upload URLs below) ends up http://, which browsers silently block as mixed
// content when the page itself is https. This is why an upload could report
// success yet the image never actually displays.
app.set('trust proxy', 1);

const PORT = process.env.PORT || 4000;
const DATA_FILE = path.join(__dirname, 'data', 'products.json');
const CUSTOMERS_FILE = path.join(__dirname, 'data', 'customers.json');
const ORDERS_FILE = path.join(__dirname, 'data', 'orders.json');
const CATEGORIES_FILE = path.join(__dirname, 'data', 'categories.json');
const SETTINGS_FILE = path.join(__dirname, 'data', 'settings.json');

if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]');
if (!fs.existsSync(CUSTOMERS_FILE)) fs.writeFileSync(CUSTOMERS_FILE, '[]');
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, '[]');
if (!fs.existsSync(CATEGORIES_FILE)) fs.writeFileSync(CATEGORIES_FILE, '[]');
if (!fs.existsSync(SETTINGS_FILE)) fs.writeFileSync(SETTINGS_FILE, '{"site_name":"BONITA","accent_color":"#7A2E27","hero":{},"delivery":{"default_fee":5000,"fees":{}},"logo_url":"","hero_media":null,"custom_style":null,"section_order":["hero","categories","products","story","newsletter"]}');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const EMAIL_FROM = process.env.EMAIL_FROM || 'BONITA <onboarding@resend.dev>';

async function sendOrderEmails(order) {
  if (!resend) return; // email not configured — order still succeeds without it
  const itemsHtml = order.items.map(i => `<li>${i.name}${i.size ? ` (مقاس ${i.size})` : ''} × ${i.qty} — ${i.price}</li>`).join('');
  const deliveryLine = `<p>التوصيل: ${order.governorate} — ${order.address}<br>رسم التوصيل: $${order.deliveryFee || 0}</p>`;

  try {
    await resend.emails.send({
      from: EMAIL_FROM,
      to: order.customerEmail,
      subject: `BONITA — تأكيد الطلب #${order.id}`,
      html: `
        <div style="font-family:sans-serif;direction:rtl;text-align:right;">
          <h2>شكراً لطلبك من BONITA، ${order.customerName}!</h2>
          <p>رقم طلبك: <strong>${order.id}</strong></p>
          <ul>${itemsHtml}</ul>
          ${deliveryLine}
          <p>المجموع الكلي: <strong>$${order.total}</strong></p>
          <p>الدفع عند الاستلام. راح نتواصل وياك قريباً لتأكيد التوصيل.</p>
        </div>`
    });
  } catch (e) {
    console.error('customer email failed:', e.message);
  }

  if (process.env.STORE_OWNER_EMAIL) {
    try {
      await resend.emails.send({
        from: EMAIL_FROM,
        to: process.env.STORE_OWNER_EMAIL,
        subject: `طلب جديد #${order.id} — $${order.total}`,
        html: `
          <div style="font-family:sans-serif;direction:rtl;text-align:right;">
            <h2>وصل طلب جديد</h2>
            <p>الزبون: ${order.customerName} (${order.customerEmail})</p>
            <ul>${itemsHtml}</ul>
            ${deliveryLine}
            <p>المجموع الكلي: <strong>$${order.total}</strong></p>
          </div>`
      });
    } catch (e) {
      console.error('store owner email failed:', e.message);
    }
  }
}

// ---------- middleware ----------
app.use(express.json());
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*', // set this to your Netlify/site URL in production
  credentials: true
}));

const isProd = process.env.NODE_ENV === 'production';

// Token-based auth (instead of cookies). Cookies don't reliably survive
// cross-site requests anymore — modern browsers (Edge/Chrome tracking
// prevention, Safari ITP) silently block a session cookie set by a
// different domain than the page (Render vs Netlify here), which makes
// login look like it works but nothing actually stays authenticated.
// Bearer tokens sent in a normal header have no such restriction.
const adminTokens = new Map();    // token -> { role, expires }
const customerTokens = new Map(); // token -> { id, name, email, expires }
const TOKEN_TTL = 1000 * 60 * 60 * 8; // 8 hours

function makeToken() {
  return require('crypto').randomBytes(24).toString('hex');
}
function cleanupExpired(map) {
  const now = Date.now();
  for (const [token, data] of map) {
    if (data.expires < now) map.delete(token);
  }
}
function getBearerToken(req) {
  const header = req.get('Authorization') || '';
  return header.startsWith('Bearer ') ? header.slice(7) : null;
}

// Lightweight CSRF mitigation: browsers only let JS set custom headers on
// same-origin or CORS-allowed requests, so a hidden cross-site <form> submit
// (classic CSRF) can never include this header. Combined with the strict
// ALLOWED_ORIGIN check above, this blocks the common CSRF attack pattern
// without needing a full token-exchange flow.
app.use((req, res, next) => {
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    if (req.get('X-Boneta-Client') !== 'boneta-app') {
      return res.status(403).json({ error: 'missing client header' });
    }
  }
  next();
});

// Login attempts are rate-limited to slow down password guessing
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many attempts — please wait a bit and try again' }
});

function requireAuth(req, res, next) {
  cleanupExpired(adminTokens);
  const token = getBearerToken(req);
  const data = token && adminTokens.get(token);
  if (data) { req.adminRole = data.role; return next(); }
  return res.status(401).json({ error: 'not authenticated' });
}

function requireOwner(req, res, next) {
  cleanupExpired(adminTokens);
  const token = getBearerToken(req);
  const data = token && adminTokens.get(token);
  if (data && data.role === 'owner') { req.adminRole = data.role; return next(); }
  return res.status(403).json({ error: 'owner access required' });
}

function requireCustomer(req, res, next) {
  cleanupExpired(customerTokens);
  const token = getBearerToken(req);
  const data = token && customerTokens.get(token);
  if (data) { req.customer = data; return next(); }
  return res.status(401).json({ error: 'not logged in' });
}

// ---------- auth ----------
app.post('/api/login', loginLimiter, async (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'password required' });
  const ownerHash = process.env.ADMIN_PASSWORD_HASH;
  const staffHash = process.env.STAFF_PASSWORD_HASH; // optional — view/update orders only, no delete or settings access
  if (!ownerHash) return res.status(500).json({ error: 'server not configured' });

  if (await bcrypt.compare(password, ownerHash)) {
    const token = makeToken();
    adminTokens.set(token, { role: 'owner', expires: Date.now() + TOKEN_TTL });
    return res.json({ ok: true, role: 'owner', token });
  }
  if (staffHash && (await bcrypt.compare(password, staffHash))) {
    const token = makeToken();
    adminTokens.set(token, { role: 'staff', expires: Date.now() + TOKEN_TTL });
    return res.json({ ok: true, role: 'staff', token });
  }
  res.status(401).json({ error: 'wrong password' });
});

app.post('/api/logout', (req, res) => {
  const token = getBearerToken(req);
  if (token) adminTokens.delete(token);
  res.json({ ok: true });
});

app.get('/api/session', (req, res) => {
  cleanupExpired(adminTokens);
  const token = getBearerToken(req);
  const data = token && adminTokens.get(token);
  res.json({ authed: !!data, role: data ? data.role : null });
});

// ---------- site settings ----------
function readSettings() {
  return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
}
function writeSettings(obj) {
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(obj, null, 2));
}

app.get('/api/settings', (req, res) => {
  res.json(readSettings());
});

app.put('/api/settings', requireOwner, (req, res) => {
  const current = readSettings();
  const incoming = req.body || {};
  const merged = {
    site_name: incoming.site_name || current.site_name,
    accent_color: incoming.accent_color || current.accent_color,
    hero: { ...current.hero, ...(incoming.hero || {}) },
    delivery: incoming.delivery ? { ...current.delivery, ...incoming.delivery } : current.delivery,
    theme: incoming.theme || current.theme,
    logo_url: incoming.logo_url !== undefined ? incoming.logo_url : current.logo_url,
    hero_media: incoming.hero_media !== undefined ? incoming.hero_media : current.hero_media,
    custom_style: incoming.custom_style ? { ...current.custom_style, ...incoming.custom_style } : current.custom_style,
    section_order: incoming.section_order || current.section_order
  };
  writeSettings(merged);
  res.json({ ok: true, settings: merged });
});

// ---------- categories ----------
function readCategories() {
  return JSON.parse(fs.readFileSync(CATEGORIES_FILE, 'utf8'));
}
function writeCategories(list) {
  fs.writeFileSync(CATEGORIES_FILE, JSON.stringify(list, null, 2));
}
function slugify(label) {
  return label.toLowerCase().replace(/[^a-z0-9\u0600-\u06FF]+/g, '-').replace(/^-+|-+$/g, '') || 'cat';
}

app.get('/api/categories', (req, res) => {
  res.json(readCategories());
});

// Bulk replace — used when applying a full design theme (which bundles its own category set)
app.put('/api/categories', requireOwner, (req, res) => {
  const incoming = req.body && req.body.categories;
  if (!Array.isArray(incoming)) return res.status(400).json({ error: 'categories array required' });
  const seen = {};
  const result = incoming.filter(c => c && c.label).map(c => {
    let key = slugify(c.label);
    let suffix = 1;
    while (seen[key]) { key = `${slugify(c.label)}-${suffix++}`; }
    seen[key] = true;
    return { key, label: c.label, color1: c.color1 || '#AD8153', color2: c.color2 || '#6B4E30', desc: c.desc || '' };
  });
  writeCategories(result);
  res.json({ ok: true, categories: result });
});

app.post('/api/categories', requireOwner, (req, res) => {
  const { label, color1, color2, desc } = req.body || {};
  if (!label) return res.status(400).json({ error: 'label required' });
  const categories = readCategories();
  let key = slugify(label);
  let suffix = 1;
  while (categories.find(c => c.key === key)) { key = `${slugify(label)}-${suffix++}`; }
  categories.push({ key, label, color1: color1 || '#AD8153', color2: color2 || '#6B4E30', desc: desc || '' });
  writeCategories(categories);
  res.json({ ok: true, categories });
});

app.put('/api/categories/:key', requireOwner, (req, res) => {
  const categories = readCategories();
  const cat = categories.find(c => c.key === req.params.key);
  if (!cat) return res.status(404).json({ error: 'not found' });
  const { label, color1, color2, desc } = req.body || {};
  if (label) cat.label = label;
  if (color1) cat.color1 = color1;
  if (color2) cat.color2 = color2;
  if (desc !== undefined) cat.desc = desc;
  writeCategories(categories);
  res.json({ ok: true, categories });
});

app.delete('/api/categories/:key', requireOwner, (req, res) => {
  let categories = readCategories();
  categories = categories.filter(c => c.key !== req.params.key);
  writeCategories(categories);
  res.json({ ok: true, categories });
});

// ---------- products ----------
function readProducts() {
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}
function writeProducts(list) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(list, null, 2));
}

app.get('/api/products', (req, res) => {
  res.json(readProducts());
});

app.post('/api/products', requireOwner, (req, res) => {
  const list = readProducts();
  list.push(req.body);
  writeProducts(list);
  res.json({ ok: true, products: list });
});

app.put('/api/products/:index', requireOwner, (req, res) => {
  const list = readProducts();
  const i = parseInt(req.params.index, 10);
  if (i < 0 || i >= list.length) return res.status(404).json({ error: 'not found' });
  list[i] = req.body;
  writeProducts(list);
  res.json({ ok: true, products: list });
});

app.delete('/api/products/:index', requireOwner, (req, res) => {
  const list = readProducts();
  const i = parseInt(req.params.index, 10);
  if (i < 0 || i >= list.length) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  writeProducts(list);
  res.json({ ok: true, products: list });
});

// ---------- customer accounts ----------
function readCustomers() {
  return JSON.parse(fs.readFileSync(CUSTOMERS_FILE, 'utf8'));
}
function writeCustomers(list) {
  fs.writeFileSync(CUSTOMERS_FILE, JSON.stringify(list, null, 2));
}

app.post('/api/register', loginLimiter, async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'missing fields' });
  const customers = readCustomers();
  if (customers.find(c => c.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: 'email already registered' });
  }
  const passwordHash = await bcrypt.hash(password, 12);
  const customer = { id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), name, email, passwordHash };
  customers.push(customer);
  writeCustomers(customers);
  const token = makeToken();
  customerTokens.set(token, { id: customer.id, name: customer.name, email: customer.email, expires: Date.now() + TOKEN_TTL });
  res.json({ ok: true, name: customer.name, token });
});

app.post('/api/customer-login', loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing fields' });
  const customers = readCustomers();
  const customer = customers.find(c => c.email.toLowerCase() === email.toLowerCase());
  if (!customer) return res.status(401).json({ error: 'wrong email or password' });
  const ok = await bcrypt.compare(password, customer.passwordHash);
  if (!ok) return res.status(401).json({ error: 'wrong email or password' });
  const token = makeToken();
  customerTokens.set(token, { id: customer.id, name: customer.name, email: customer.email, expires: Date.now() + TOKEN_TTL });
  res.json({ ok: true, name: customer.name, token });
});

app.post('/api/customer-logout', (req, res) => {
  const token = getBearerToken(req);
  if (token) customerTokens.delete(token);
  res.json({ ok: true });
});

app.get('/api/customer-session', (req, res) => {
  cleanupExpired(customerTokens);
  const token = getBearerToken(req);
  const data = token && customerTokens.get(token);
  res.json({ authed: !!data, name: data ? data.name : null });
});

// ---------- orders ----------
function readOrders() {
  return JSON.parse(fs.readFileSync(ORDERS_FILE, 'utf8'));
}
function writeOrders(list) {
  fs.writeFileSync(ORDERS_FILE, JSON.stringify(list, null, 2));
}

app.post('/api/orders', requireCustomer, (req, res) => {
  const { items, total, governorate, address } = req.body || {};
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'empty order' });
  if (!governorate || !address) return res.status(400).json({ error: 'delivery details required' });

  const products = readProducts();

  // validate stock first (only for products that actually track sizes/stock — older
  // products without a `sizes` field are treated as unlimited for backward compatibility)
  for (const item of items) {
    const product = products.find(p => p.name === item.name);
    if (product && product.sizes && item.size) {
      const available = product.sizes[item.size] || 0;
      if (available < item.qty) {
        return res.status(409).json({ error: `insufficient_stock`, item: item.name, size: item.size, available });
      }
    }
  }
  // stock confirmed available — now decrement
  for (const item of items) {
    const product = products.find(p => p.name === item.name);
    if (product && product.sizes && item.size) {
      product.sizes[item.size] -= item.qty;
    }
  }
  writeProducts(products);

  const settings = readSettings();
  const deliveryFee = (settings.delivery && settings.delivery.fees && settings.delivery.fees[governorate] !== undefined)
    ? settings.delivery.fees[governorate]
    : (settings.delivery ? settings.delivery.default_fee : 0);

  const orders = readOrders();
  const order = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    customerId: req.customer.id,
    customerName: req.customer.name,
    customerEmail: req.customer.email,
    items,
    subtotal: total,
    governorate, address,
    deliveryFee,
    total: total + deliveryFee,
    status: 'new',
    createdAt: new Date().toISOString()
  };
  orders.push(order);
  writeOrders(orders);
  res.json({ ok: true, orderId: order.id, deliveryFee, total: order.total });
  sendOrderEmails(order); // fire-and-forget — order is already confirmed to the customer either way
});

// customer's own order history
app.get('/api/my-orders', requireCustomer, (req, res) => {
  const orders = readOrders().filter(o => o.customerId === req.customer.id);
  res.json(orders);
});

// admin view of all orders
app.get('/api/orders', requireAuth, (req, res) => {
  res.json(readOrders());
});

app.put('/api/orders/:id/status', requireAuth, (req, res) => {
  const { status } = req.body || {};
  const orders = readOrders();
  const order = orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'not found' });
  order.status = status;
  writeOrders(orders);
  res.json({ ok: true });
});


const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
app.use('/uploads', express.static(UPLOADS_DIR));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25MB — enough for a short hero background video
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/') && !file.mimetype.startsWith('video/')) {
      return cb(new Error('only image or video files allowed'));
    }
    cb(null, true);
  }
});

app.post('/api/upload', requireOwner, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'no file' });

  // Prefer Cloudinary if configured (images survive redeploys). If not configured —
  // e.g. Cloudinary isn't available in the owner's country — fall back automatically
  // to storing the file directly on this server's disk. That works everywhere with
  // no external account, at the cost of images being wiped on the next code redeploy
  // (not on normal restarts — only when you push new code to GitHub).
  if (process.env.CLOUDINARY_CLOUD_NAME) {
    const resourceType = req.file.mimetype.startsWith('video/') ? 'video' : 'image';
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder: 'boneta', resource_type: resourceType },
      (err, result) => {
        if (err) return res.status(500).json({ error: 'upload failed' });
        res.json({ url: result.secure_url });
      }
    );
    Readable.from(req.file.buffer).pipe(uploadStream);
  } else {
    const ext = path.extname(req.file.originalname) || '.jpg';
    const filename = `${Date.now()}-${Math.round(Math.random() * 1e6)}${ext}`;
    fs.writeFile(path.join(UPLOADS_DIR, filename), req.file.buffer, (err) => {
      if (err) return res.status(500).json({ error: 'upload failed' });
      const protocol = isProd ? 'https' : req.protocol; // belt-and-suspenders alongside trust proxy above
      const baseUrl = `${protocol}://${req.get('host')}`;
      res.json({ url: `${baseUrl}/uploads/${filename}` });
    });
  }
});

app.listen(PORT, () => console.log(`BONITA API running on port ${PORT}`));
