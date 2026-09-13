require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { Resend } = require('resend');
const rateLimit = require('express-rate-limit');
const { Readable } = require('stream');
const { MongoClient, GridFSBucket, ObjectId } = require('mongodb');

const app = express();
// Render (and most hosts) sit behind a reverse proxy that terminates HTTPS and
// forwards plain HTTP internally. Without this, req.protocol always reports
// 'http' even on a live https:// site — any URL we build from it ends up
// http://, which browsers silently block as mixed content when the page
// itself is https.
app.set('trust proxy', 1);

const PORT = process.env.PORT || 4000;
const isProd = process.env.NODE_ENV === 'production';

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

// =========================================================================
// DATABASE (MongoDB Atlas)
// Every collection holds ONE document with _id:'singleton' and a `list`
// field (or, for settings, the settings fields directly). This keeps the
// exact same array-based data shape the rest of this file already expects —
// only the storage layer underneath changed, from flat JSON files (wiped
// whenever Render's free-tier filesystem resets) to a real persistent
// database that survives restarts, redeploys, and sleep/wake cycles.
// =========================================================================
let db, bucket;
if (!process.env.MONGODB_URI) {
  console.error('MONGODB_URI is not set. Add it in your Render Environment settings — see .env.example.');
  process.exit(1);
}
const mongoClient = new MongoClient(process.env.MONGODB_URI);

const SEED = {
  products: [
    { name: "Marrow Ankle Boot", cat: "boots", price: "$385", color1: "#8E6A3F", color2: "#5A3E22", img: "" },
    { name: "Waist Slingback", cat: "heels", price: "$295", color1: "#7A3E3E", color2: "#4E2323", img: "" },
    { name: "Last-Line Sandal", cat: "sandals", price: "$245", color1: "#5F6B57", color2: "#37402F", img: "" },
    { name: "Vamp Loafer", cat: "flats", price: "$265", color1: "#4C463C", color2: "#231F19", img: "" },
    { name: "Toe-Box Mule", cat: "heels", price: "$310", color1: "#AD8153", color2: "#7A5A38", img: "" },
    { name: "Arch Platform Sandal", cat: "sandals", price: "$275", color1: "#A9A398", color2: "#726C60", img: "" },
    { name: "Heel-Cap Bootie", cat: "boots", price: "$355", color1: "#7A2E27", color2: "#4A1B17", img: "" },
    { name: "Instep Tote", cat: "access", price: "$420", color1: "#8E6A3F", color2: "#4C3720", img: "" }
  ],
  categories: [
    { key: "boots", label: "Boots & Booties", color1: "#8E6A3F", color2: "#5A3E22", desc: "Structure that carries you through cold seasons." },
    { key: "sandals", label: "Sandals", color1: "#5F6B57", color2: "#37402F", desc: "Light, open, and built for warm days." },
    { key: "heels", label: "Pumps & Heels", color1: "#7A3E3E", color2: "#4E2323", desc: "Height with a stable, well-built base." },
    { key: "flats", label: "Flats", color1: "#4C463C", color2: "#231F19", desc: "Everyday comfort without losing shape." },
    { key: "access", label: "Accessories", color1: "#A9A398", color2: "#726C60", desc: "The details that finish a look." }
  ],
  customers: [],
  orders: [],
  settings: {
    site_name: "BONITA", accent_color: "#7A2E27",
    hero: {
      en: { title: "Structure in every step.", subtitle: "Every BONITA silhouette is built from the last outward — the hidden armature that gives a shoe its posture. We just don't hide it anymore." },
      ar: { title: "هيكل في كل خطوة.", subtitle: "كل قطعة من بونيتا تُبنى من الأساس الخشبي للحذاء نحو الخارج — الهيكل الخفي اللي يعطيه ثباته. إحنا بس ما نخفيه بعد." },
      ku: { title: "پێکهاتە لە هەر هەنگاوێکدا.", subtitle: "هەر شێوازێکی بۆنیتا لەسەر بنەمای پێڵاو دروست دەبێت — ئەو پێکهاتە شاراوەیەی وەستایی پێدەبەخشێت. ئێمە تەنها چیتر شاردنیەوەمان نییە." },
      tr: { title: "Her adımda yapı.", subtitle: "Her BONITA modeli kalıptan dışa doğru inşa edilir — ayakkabıya duruşunu veren gizli iskelet. Artık onu saklamıyoruz." },
      fa: { title: "ساختار در هر قدم.", subtitle: "هر مدل بونیتا از روی قالب کفش به بیرون ساخته می‌شود — اسکلت پنهانی که به کفش ایستادگی می‌دهد. ما دیگر آن را پنهان نمی‌کنیم." }
    },
    delivery: {
      default_fee: 5000,
      fees: { "بغداد":3000, "البصرة":6000, "نينوى":6000, "أربيل":6000, "النجف":5000, "كربلاء":5000, "بابل":4000, "الأنبار":6000, "ذي قار":6000, "ديالى":5000, "كركوك":6000, "واسط":5000, "ميسان":6000, "القادسية":5000, "صلاح الدين":5500, "دهوك":7000, "السليمانية":7000, "المثنى":6000 }
    },
    theme: {
      id: "boneta-classic",
      palette: { bone:"#E9E3D4", boneSoft:"#F3EFE5", ink:"#211C16", marrow:"#7A2E27", brass:"#AD8153", stone:"#A39B8B" },
      font: "editorial", gridCols: 4, catCols: 4, radius: 0
    },
    logo_url: "", hero_media: null, custom_style: null,
    section_order: ["hero", "categories", "products", "story", "newsletter"]
  }
};

async function connectDB() {
  await mongoClient.connect();
  db = mongoClient.db('bonita');
  bucket = new GridFSBucket(db, { bucketName: 'uploads' });
  console.log('Connected to MongoDB Atlas');
}

async function readList(name) {
  const doc = await db.collection(name).findOne({ _id: 'singleton' });
  if (doc) return doc.list;
  await db.collection(name).insertOne({ _id: 'singleton', list: SEED[name] });
  return SEED[name];
}
async function writeList(name, list) {
  await db.collection(name).updateOne({ _id: 'singleton' }, { $set: { list } }, { upsert: true });
}

async function readProducts() { return readList('products'); }
async function writeProducts(list) { return writeList('products', list); }
async function readCategories() { return readList('categories'); }
async function writeCategories(list) { return writeList('categories', list); }
async function readCustomers() { return readList('customers'); }
async function writeCustomers(list) { return writeList('customers', list); }
async function readOrders() { return readList('orders'); }
async function writeOrders(list) { return writeList('orders', list); }

async function readSettings() {
  const doc = await db.collection('settings').findOne({ _id: 'singleton' });
  if (doc) { const { _id, ...settings } = doc; return settings; }
  await db.collection('settings').insertOne({ _id: 'singleton', ...SEED.settings });
  return SEED.settings;
}
async function writeSettings(settings) {
  await db.collection('settings').updateOne({ _id: 'singleton' }, { $set: settings }, { upsert: true });
}

function slugify(label) {
  return label.toLowerCase().replace(/[^a-z0-9\u0600-\u06FF]+/g, '-').replace(/^-+|-+$/g, '') || 'cat';
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
app.get('/api/settings', async (req, res) => {
  res.json(await readSettings());
});

app.put('/api/settings', requireOwner, async (req, res) => {
  const current = await readSettings();
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
  await writeSettings(merged);
  res.json({ ok: true, settings: merged });
});

// ---------- categories ----------
app.get('/api/categories', async (req, res) => {
  res.json(await readCategories());
});

// Bulk replace — used when applying a full design theme (which bundles its own category set)
app.put('/api/categories', requireOwner, async (req, res) => {
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
  await writeCategories(result);
  res.json({ ok: true, categories: result });
});

app.post('/api/categories', requireOwner, async (req, res) => {
  const { label, color1, color2, desc } = req.body || {};
  if (!label) return res.status(400).json({ error: 'label required' });
  const categories = await readCategories();
  let key = slugify(label);
  let suffix = 1;
  while (categories.find(c => c.key === key)) { key = `${slugify(label)}-${suffix++}`; }
  categories.push({ key, label, color1: color1 || '#AD8153', color2: color2 || '#6B4E30', desc: desc || '' });
  await writeCategories(categories);
  res.json({ ok: true, categories });
});

app.put('/api/categories/:key', requireOwner, async (req, res) => {
  const categories = await readCategories();
  const cat = categories.find(c => c.key === req.params.key);
  if (!cat) return res.status(404).json({ error: 'not found' });
  const { label, color1, color2, desc } = req.body || {};
  if (label) cat.label = label;
  if (color1) cat.color1 = color1;
  if (color2) cat.color2 = color2;
  if (desc !== undefined) cat.desc = desc;
  await writeCategories(categories);
  res.json({ ok: true, categories });
});

app.delete('/api/categories/:key', requireOwner, async (req, res) => {
  let categories = await readCategories();
  categories = categories.filter(c => c.key !== req.params.key);
  await writeCategories(categories);
  res.json({ ok: true, categories });
});

// ---------- products ----------
app.get('/api/products', async (req, res) => {
  res.json(await readProducts());
});

app.post('/api/products', requireOwner, async (req, res) => {
  const list = await readProducts();
  list.push(req.body);
  await writeProducts(list);
  res.json({ ok: true, products: list });
});

app.put('/api/products/:index', requireOwner, async (req, res) => {
  const list = await readProducts();
  const i = parseInt(req.params.index, 10);
  if (i < 0 || i >= list.length) return res.status(404).json({ error: 'not found' });
  list[i] = req.body;
  await writeProducts(list);
  res.json({ ok: true, products: list });
});

app.delete('/api/products/:index', requireOwner, async (req, res) => {
  const list = await readProducts();
  const i = parseInt(req.params.index, 10);
  if (i < 0 || i >= list.length) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  await writeProducts(list);
  res.json({ ok: true, products: list });
});

// ---------- customer accounts ----------
app.post('/api/register', loginLimiter, async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'missing fields' });
  const customers = await readCustomers();
  if (customers.find(c => c.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: 'email already registered' });
  }
  const passwordHash = await bcrypt.hash(password, 12);
  const customer = { id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), name, email, passwordHash };
  customers.push(customer);
  await writeCustomers(customers);
  const token = makeToken();
  customerTokens.set(token, { id: customer.id, name: customer.name, email: customer.email, expires: Date.now() + TOKEN_TTL });
  res.json({ ok: true, name: customer.name, token });
});

app.post('/api/customer-login', loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing fields' });
  const customers = await readCustomers();
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
app.post('/api/orders', requireCustomer, async (req, res) => {
  const { items, total, governorate, address } = req.body || {};
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'empty order' });
  if (!governorate || !address) return res.status(400).json({ error: 'delivery details required' });

  const products = await readProducts();

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
  await writeProducts(products);

  const settings = await readSettings();
  const deliveryFee = (settings.delivery && settings.delivery.fees && settings.delivery.fees[governorate] !== undefined)
    ? settings.delivery.fees[governorate]
    : (settings.delivery ? settings.delivery.default_fee : 0);

  const orders = await readOrders();
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
  await writeOrders(orders);
  res.json({ ok: true, orderId: order.id, deliveryFee, total: order.total });
  sendOrderEmails(order); // fire-and-forget — order is already confirmed to the customer either way
});

// customer's own order history
app.get('/api/my-orders', requireCustomer, async (req, res) => {
  const orders = await readOrders();
  res.json(orders.filter(o => o.customerId === req.customer.id));
});

// admin view of all orders
app.get('/api/orders', requireAuth, async (req, res) => {
  res.json(await readOrders());
});

app.put('/api/orders/:id/status', requireAuth, async (req, res) => {
  const { status } = req.body || {};
  const orders = await readOrders();
  const order = orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'not found' });
  order.status = status;
  await writeOrders(orders);
  res.json({ ok: true });
});

// ---------- image / video upload ----------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB — practical ceiling on a free-tier host with limited RAM (files are buffered in memory before upload)
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/') && !file.mimetype.startsWith('video/')) {
      return cb(new Error('only image or video files allowed'));
    }
    cb(null, true);
  }
});

app.post('/api/upload', requireOwner, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'no file' });

  // Prefer Cloudinary if configured (purpose-built CDN for media). If not
  // configured or it fails, fall back to storing the file in MongoDB itself
  // via GridFS — this persists reliably across Render restarts/redeploys,
  // unlike the server's local disk which the free tier wipes periodically.
  if (process.env.CLOUDINARY_CLOUD_NAME) {
    const resourceType = req.file.mimetype.startsWith('video/') ? 'video' : 'image';
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder: 'boneta', resource_type: resourceType },
      (err, result) => {
        if (err) {
          console.error('Cloudinary upload failed, falling back to GridFS:', err.message);
          storeInGridFS();
          return;
        }
        res.json({ url: result.secure_url });
      }
    );
    Readable.from(req.file.buffer).pipe(uploadStream);
    return;
  }
  storeInGridFS();

  function storeInGridFS() {
    if (res.headersSent) return;
    const filename = `${Date.now()}-${Math.round(Math.random() * 1e6)}`;
    const gridStream = bucket.openUploadStream(filename, { contentType: req.file.mimetype });
    gridStream.end(req.file.buffer);
    gridStream.on('finish', () => {
      const protocol = isProd ? 'https' : req.protocol;
      const baseUrl = `${protocol}://${req.get('host')}`;
      res.json({ url: `${baseUrl}/api/files/${gridStream.id}` });
    });
    gridStream.on('error', (err) => {
      console.error('GridFS upload failed:', err.message);
      res.status(500).json({ error: 'upload failed' });
    });
  }
});

// Serves images/videos stored via the GridFS fallback above
app.get('/api/files/:id', async (req, res) => {
  let objectId;
  try { objectId = new ObjectId(req.params.id); } catch (e) { return res.sendStatus(404); }
  const fileDoc = await db.collection('uploads.files').findOne({ _id: objectId });
  if (!fileDoc) return res.sendStatus(404);
  res.set('Content-Type', fileDoc.contentType || 'application/octet-stream');
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  bucket.openDownloadStream(objectId)
    .on('error', () => res.sendStatus(404))
    .pipe(res);
});

// Catches errors from multer (e.g. file too large) and anything else that
// falls through, so the client always gets clean JSON instead of a crash page.
app.use((err, req, res, next) => {
  if (err && err.name === 'MulterError') {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'file_too_large', message: 'الملف أكبر من الحد المسموح (100 ميجابايت).' });
    }
    return res.status(400).json({ error: 'upload_error', message: err.message });
  }
  if (err && err.message === 'only image or video files allowed') {
    return res.status(400).json({ error: 'invalid_file_type', message: err.message });
  }
  if (err) {
    console.error(err);
    return res.status(500).json({ error: 'server_error' });
  }
  next();
});

connectDB()
  .then(() => {
    app.listen(PORT, () => console.log(`BONITA API running on port ${PORT}`));
  })
  .catch((err) => {
    console.error('Failed to connect to MongoDB:', err.message);
    process.exit(1);
  });
