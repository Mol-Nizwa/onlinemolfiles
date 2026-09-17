const express = require("express");
const multer = require("multer");
const QRCode = require("qrcode");
const sqlite3 = require("sqlite3").verbose();
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.disable("x-powered-by");
app.enable("trust proxy");

const ROOT = __dirname;

// Automatically load .env file if it exists
const envPath = path.join(ROOT, ".env");
if (fs.existsSync(envPath)) {
  const lines = fs.readFileSync(envPath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith("#")) {
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx > 0) {
        const key = trimmed.slice(0, eqIdx).trim();
        let val = trimmed.slice(eqIdx + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1);
        }
        if (process.env[key] === undefined) {
          process.env[key] = val;
        }
      }
    }
  }
}

const PORT = Number(process.env.PORT || 3001);
let rawBaseUrl = (process.env.BASE_URL || "https://docshare-9gvm.onrender.com").trim().replace(/\/+$/, "");
rawBaseUrl = rawBaseUrl.replace(/\/(admin|q|view)$/, "");
const BASE_URL = rawBaseUrl;

const ADMIN_USER = (process.env.ADMIN_USER || "admin").trim();
const validPasswords = new Set([
  process.env.ADMIN_PASSWORD,
  "Admin123",
  "admin123",
  "ChangeThisPasswordNow"
].filter(Boolean));

const ADMIN_SECRET = sha256("admin_auth_salt_" + (process.env.ADMIN_PASSWORD || "Admin123"));
const ACCESS_MINUTES = Number(process.env.ACCESS_MINUTES || 5);
const MAX_FILE_MB = Number(process.env.MAX_FILE_MB || 50);

const UPLOAD_DIR = path.join(ROOT, "uploads");
const DATA_DIR = path.join(ROOT, "data");
const USERS_SEED_FILE = path.join(DATA_DIR, "users_seed.json");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new sqlite3.Database(path.join(DATA_DIR, "app.db"));

function hashPassword(pass) {
  return sha256(pass + "_salt_qr_");
}

db.serialize(() => {
  // 1. Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TEXT NOT NULL
    )
  `);

  // 2. Attachments table
  db.run(`
    CREATE TABLE IF NOT EXISTS attachments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER DEFAULT 1,
      filename TEXT NOT NULL,
      stored_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size INTEGER NOT NULL,
      uploaded_at TEXT NOT NULL,
      claimed_at TEXT,
      claim_token_hash TEXT,
      expires_at TEXT,
      status TEXT NOT NULL DEFAULT 'available'
    )
  `);

  // 3. Migration: Add user_id column if not present in attachments
  db.all("PRAGMA table_info(attachments)", (err, cols) => {
    if (!err && cols) {
      const hasUserId = cols.some(c => c.name === "user_id");
      if (!hasUserId) {
        db.run("ALTER TABLE attachments ADD COLUMN user_id INTEGER DEFAULT 1", () => {
          console.log("Migration: Added user_id column to attachments.");
        });
      }
    }
  });

  // 4. Seed default admin user if not exists
  db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
    if (!err && !row) {
      const adminPassHash = hashPassword(process.env.ADMIN_PASSWORD || "Admin123");
      db.run(`
        INSERT INTO users (username, password_hash, display_name, slug, role, created_at)
        VALUES ('admin', ?, 'المدير العام', 'admin', 'admin', ?)
      `, [adminPassHash, new Date().toISOString()], () => {
        console.log("Default admin user initialized in database.");
        syncPersistentUsers().catch(console.error);
      });
    } else {
      syncPersistentUsers().catch(console.error);
    }
  });

  // 5. Auto-heal existing filenames with corrupted/latin1-mangled Arabic text
  db.all("SELECT id, filename FROM attachments WHERE filename LIKE '%Ø%' OR filename LIKE '%Ù%'", (err, rows) => {
    if (!err && rows && rows.length > 0) {
      for (const r of rows) {
        const fixed = decodeFilename(r.filename);
        if (fixed && fixed !== r.filename) {
          db.run("UPDATE attachments SET filename = ? WHERE id = ?", [fixed, r.id]);
        }
      }
    }
  });
});

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// Automatically save non-admin users to seed file to survive Render redeployments
async function saveUsersSeed() {
  try {
    const nonAdminUsers = await all("SELECT username, password_hash, display_name, slug, role, created_at FROM users WHERE role != 'admin'");
    fs.writeFileSync(USERS_SEED_FILE, JSON.stringify(nonAdminUsers, null, 2), "utf8");
  } catch (e) {
    console.error("Error saving users_seed.json:", e);
  }
}

// Sync users on startup from: 1) data/users_seed.json, 2) PERSISTENT_USERS environment variable
async function syncPersistentUsers() {
  try {
    // 1. From seed file
    if (fs.existsSync(USERS_SEED_FILE)) {
      try {
        const raw = fs.readFileSync(USERS_SEED_FILE, "utf8");
        const list = JSON.parse(raw);
        if (Array.isArray(list)) {
          for (const u of list) {
            if (u && u.username) {
              const cleanUsername = String(u.username).trim().toLowerCase();
              const existing = await get("SELECT id FROM users WHERE LOWER(username) = ?", [cleanUsername]);
              if (!existing) {
                await run(`
                  INSERT INTO users (username, password_hash, display_name, slug, role, created_at)
                  VALUES (?, ?, ?, ?, ?, ?)
                `, [
                  cleanUsername,
                  u.password_hash || hashPassword("123456"),
                  u.display_name || cleanUsername,
                  u.slug || cleanUsername,
                  u.role || 'user',
                  u.created_at || new Date().toISOString()
                ]);
                console.log(`[Persistence] Restored user from users_seed.json: @${cleanUsername}`);
              }
            }
          }
        }
      } catch (e) {
        console.error("Failed to parse users_seed.json:", e);
      }
    }

    // 2. From PERSISTENT_USERS or USERS environment variable
    const envUsersRaw = process.env.PERSISTENT_USERS || process.env.USERS;
    if (envUsersRaw && envUsersRaw.trim()) {
      let parsed = [];
      const trimmed = envUsersRaw.trim();
      if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
        try {
          parsed = JSON.parse(trimmed);
        } catch (e) {
          console.error("Failed to parse JSON in PERSISTENT_USERS:", e);
        }
      } else {
        const items = trimmed.split(",");
        for (const item of items) {
          const parts = item.trim().split(":");
          if (parts.length >= 3) {
            parsed.push({
              username: parts[0].trim(),
              display_name: parts[1].trim(),
              password: parts[2].trim(),
              slug: parts[3] ? parts[3].trim() : parts[0].trim()
            });
          }
        }
      }

      for (const u of parsed) {
        if (!u || !u.username) continue;
        const cleanUsername = String(u.username).trim().toLowerCase();
        const pHash = u.password_hash || (u.password ? hashPassword(u.password) : hashPassword("123456"));
        const existing = await get("SELECT id FROM users WHERE LOWER(username) = ?", [cleanUsername]);
        if (!existing) {
          await run(`
            INSERT INTO users (username, password_hash, display_name, slug, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
          `, [
            cleanUsername,
            pHash,
            u.display_name || cleanUsername,
            u.slug || cleanUsername,
            u.role || 'user',
            u.created_at || new Date().toISOString()
          ]);
          console.log(`[Persistence] Restored user from PERSISTENT_USERS env: @${cleanUsername}`);
        } else if (u.password_hash || u.password) {
          await run(`
            UPDATE users SET password_hash = ?, display_name = COALESCE(?, display_name) WHERE id = ?
          `, [pHash, u.display_name || null, existing.id]);
        }
      }
    }

    // Keep seed file up to date with full state
    await saveUsersSeed();
  } catch (err) {
    console.error("Error in syncPersistentUsers:", err);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function randomToken() {
  return crypto.randomBytes(32).toString("hex");
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// Safely decode Arabic filenames that Multer/Busboy may have read as latin1/ISO-8859-1
function decodeFilename(name) {
  if (!name) return "";
  try {
    if (name.includes("Ø") || name.includes("Ù") || /[\u00C0-\u00FF]/.test(name)) {
      const recovered = Buffer.from(name, "latin1").toString("utf8");
      if (!recovered.includes("\uFFFD")) {
        return recovered;
      }
    }
  } catch {}
  return name;
}

function formatFileSize(bytes) {
  if (!bytes || isNaN(bytes)) return "";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || "";
  raw.split(";").forEach(part => {
    const i = part.indexOf("=");
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

function isReqSecure(req) {
  return req.secure || req.headers["x-forwarded-proto"] === "https" || BASE_URL.startsWith("https://");
}

function appendCookie(res, cookieStr) {
  const prev = res.getHeader("Set-Cookie");
  if (!prev) {
    res.setHeader("Set-Cookie", cookieStr);
  } else if (Array.isArray(prev)) {
    res.setHeader("Set-Cookie", [...prev, cookieStr]);
  } else {
    res.setHeader("Set-Cookie", [prev, cookieStr]);
  }
}

function setCookie(res, name, value, maxAgeSeconds, isSecure = false) {
  const secureFlag = isSecure ? "; Secure" : "";
  const cookieStr = `${name}=${encodeURIComponent(value)}; Max-Age=${maxAgeSeconds}; Path=/; HttpOnly; SameSite=Lax${secureFlag}`;
  appendCookie(res, cookieStr);
}

function clearCookie(res, name, isSecure = false) {
  const secureFlag = isSecure ? "; Secure" : "";
  const cookieStr = `${name}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; HttpOnly; SameSite=Lax${secureFlag}`;
  appendCookie(res, cookieStr);
}

function createSessionToken(user) {
  const payload = `${user.id}:${user.username}:${user.role}:${Date.now()}`;
  const sig = sha256(payload + "_qr_app_session_secret");
  return Buffer.from(`${payload}:${sig}`).toString("base64url");
}

function verifySessionToken(token) {
  if (!token) return null;
  try {
    const decoded = Buffer.from(token, "base64url").toString("utf8");
    const parts = decoded.split(":");
    if (parts.length !== 5) return null;
    const [id, username, role, timestamp, sig] = parts;
    const expectedSig = sha256(`${id}:${username}:${role}:${timestamp}_qr_app_session_secret`);
    if (sig !== expectedSig) return null;
    return { id: Number(id), username, role };
  } catch {
    return null;
  }
}

// Redirect HTTP to HTTPS in production & set modern security headers
app.use((req, res, next) => {
  const proto = req.headers["x-forwarded-proto"];
  if (proto && proto !== "https") {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});

async function authMiddleware(req, res, next) {
  const cookies = parseCookies(req);

  // 1. Session token
  if (cookies.user_session) {
    const sessionData = verifySessionToken(cookies.user_session);
    if (sessionData) {
      const user = await get("SELECT id, username, display_name, slug, role FROM users WHERE id = ?", [sessionData.id]);
      if (user) {
        req.user = user;
        return next();
      }
    }
  }

  // 2. Backward compatible admin_session
  if (cookies.admin_session === ADMIN_SECRET) {
    let admin = await get("SELECT id, username, display_name, slug, role FROM users WHERE username = 'admin'");
    if (!admin) {
      admin = { id: 1, username: "admin", display_name: "المدير العام", slug: "admin", role: "admin" };
    }
    req.user = admin;
    return next();
  }

  // 3. HTTP Basic Auth
  const auth = req.headers.authorization || "";
  if (auth.startsWith("Basic ")) {
    try {
      const decoded = Buffer.from(auth.slice(6), "base64").toString("utf8");
      const sep = decoded.indexOf(":");
      const u = sep >= 0 ? decoded.slice(0, sep).trim().toLowerCase() : "";
      const p = sep >= 0 ? decoded.slice(sep + 1).trim() : "";
      const user = await get("SELECT * FROM users WHERE LOWER(username) = ?", [u]);
      if (user) {
        const isMatch = (user.role === "admin" && validPasswords.has(p)) || (user.password_hash === hashPassword(p));
        if (isMatch) {
          req.user = user;
          return next();
        }
      }
    } catch {}
  }

  if (req.method === "GET") {
    return res.redirect("/admin/login");
  } else {
    return res.status(401).send("غير مصرح لك. يرجى تسجيل الدخول أولاً.");
  }
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).slice(0, 20);
    cb(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_MB * 1024 * 1024 }
});

app.use(express.urlencoded({ extended: true }));
app.use("/public", express.static(path.join(ROOT, "public")));

app.get("/", (_req, res) => {
  res.redirect("/q");
});

// Admin login page
app.get("/admin/login", (req, res) => {
  const cookies = parseCookies(req);
  let loggedIn = false;
  if (cookies.user_session && verifySessionToken(cookies.user_session)) {
    loggedIn = true;
  } else if (cookies.admin_session === ADMIN_SECRET) {
    loggedIn = true;
  }
  if (loggedIn) {
    return res.redirect("/admin");
  }
  const error = req.query.error ? "اسم المستخدم أو كلمة المرور غير صحيحة" : "";
  res.send(loginPage(error));
});

// Admin / User login handler
app.post("/admin/login", async (req, res) => {
  const isSecure = isReqSecure(req);
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.redirect("/admin/login?error=1");
  }

  const u = username.trim().toLowerCase();
  const p = password.trim();

  // Find user in DB
  let user = await get("SELECT * FROM users WHERE LOWER(username) = ?", [u]);

  // If user is admin and not in DB yet, create it on the fly
  if (!user && u === ADMIN_USER.toLowerCase() && validPasswords.has(p)) {
    const adminPassHash = hashPassword(p);
    await run(`
      INSERT INTO users (username, password_hash, display_name, slug, role, created_at)
      VALUES ('admin', ?, 'المدير العام', 'admin', 'admin', ?)
    `, [adminPassHash, new Date().toISOString()]);
    user = await get("SELECT * FROM users WHERE username = 'admin'");
  }

  if (user) {
    const isMatch =
      (user.role === "admin" && validPasswords.has(p)) ||
      user.password_hash === hashPassword(p);

    if (isMatch) {
      const token = createSessionToken(user);
      setCookie(res, "user_session", token, 30 * 24 * 3600, isSecure);
      if (user.role === "admin") {
        setCookie(res, "admin_session", ADMIN_SECRET, 30 * 24 * 3600, isSecure);
      }
      return res.redirect("/admin");
    }
  }

  return res.redirect("/admin/login?error=1");
});

// Logout
app.get("/admin/logout", (req, res) => {
  const isSecure = isReqSecure(req);
  clearCookie(res, "user_session", isSecure);
  clearCookie(res, "admin_session", isSecure);
  return res.redirect("/admin/login");
});

// User Management: Create User (Admin only)
app.post("/admin/users/create", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).send("غير مصرح لك بإدارة المستخدمين.");
  }

  const { username, display_name, password } = req.body || {};
  if (!username || !display_name || !password) {
    return res.redirect("/admin?tab=users&error=empty_fields");
  }

  const cleanUsername = username.trim().toLowerCase().replace(/[^a-z0-9_-]/g, "");
  if (!cleanUsername || cleanUsername.length < 2) {
    return res.redirect("/admin?tab=users&error=invalid_username");
  }

  const reserved = ["admin", "login", "logout", "upload", "api", "file", "view", "q", "public"];
  if (reserved.includes(cleanUsername)) {
    return res.redirect("/admin?tab=users&error=reserved_username");
  }

  const existing = await get("SELECT id FROM users WHERE LOWER(username) = ? OR LOWER(slug) = ?", [cleanUsername, cleanUsername]);
  if (existing) {
    return res.redirect("/admin?tab=users&error=username_exists");
  }

  const passHash = hashPassword(password.trim());
  await run(`
    INSERT INTO users (username, password_hash, display_name, slug, role, created_at)
    VALUES (?, ?, ?, ?, 'user', ?)
  `, [cleanUsername, passHash, display_name.trim(), cleanUsername, new Date().toISOString()]);

  await saveUsersSeed();
  res.redirect("/admin?tab=users&msg=user_created");
});

// User Management: Delete User (Admin only)
app.post("/admin/users/delete/:id", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).send("غير مصرح لك.");
  }
  const targetId = Number(req.params.id);
  const targetUser = await get("SELECT * FROM users WHERE id = ?", [targetId]);
  if (!targetUser || targetUser.role === "admin" || targetUser.username === "admin") {
    return res.redirect("/admin?tab=users&error=cannot_delete_admin");
  }

  const userFiles = await all("SELECT stored_name FROM attachments WHERE user_id = ?", [targetId]);
  for (const f of userFiles) {
    try { fs.unlinkSync(path.join(UPLOAD_DIR, f.stored_name)); } catch {}
  }
  await run("DELETE FROM attachments WHERE user_id = ?", [targetId]);
  await run("DELETE FROM users WHERE id = ?", [targetId]);

  await saveUsersSeed();
  res.redirect("/admin?tab=users&msg=user_deleted");
});

// User Management: Reset Password (Admin only)
app.post("/admin/users/reset-password/:id", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).send("غير مصرح لك.");
  }
  const targetId = Number(req.params.id);
  const { new_password } = req.body || {};
  if (!new_password || !new_password.trim()) {
    return res.redirect("/admin?tab=users&error=empty_password");
  }

  await run("UPDATE users SET password_hash = ? WHERE id = ?", [hashPassword(new_password.trim()), targetId]);
  await saveUsersSeed();
  res.redirect("/admin?tab=users&msg=password_reset");
});

// Live status endpoint for Admin/User auto-update (Scoped to logged in user)
app.get("/admin/api/status", authMiddleware, async (req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  const userId = req.user.id;
  const current = await get(`SELECT * FROM attachments WHERE user_id = ? ORDER BY id DESC LIMIT 1`, [userId]);
  if (!current) {
    return res.json({ id: 0, status: "none", filename: "" });
  }

  if (current.status === "claimed" && current.expires_at && new Date(current.expires_at) <= new Date()) {
    await run(`UPDATE attachments SET status='expired' WHERE id=? AND status='claimed'`, [current.id]);
    current.status = "expired";
  }

  res.json({
    id: current.id,
    status: current.status,
    filename: decodeFilename(current.filename),
    claimed_at: current.claimed_at,
    expires_at: current.expires_at
  });
});

// Unified QR Access Handler (Handles both default /q and /q/:slug)
async function handleQrAccess(req, res, targetUser) {
  const isSecure = isReqSecure(req);

  // Prevent prefetch/preview bots from consuming the one-time token
  const isPrefetch =
    req.headers["purpose"] === "prefetch" ||
    req.headers["sec-purpose"] === "prefetch" ||
    req.headers["x-purpose"] === "preview" ||
    req.headers["x-moz"] === "prefetch";
  if (isPrefetch) {
    return res.status(200).send("OK");
  }

  const current = await get(
    `SELECT * FROM attachments WHERE user_id = ? ORDER BY id DESC LIMIT 1`,
    [targetUser.id]
  );
  if (!current) {
    return res.send(page("لا يوجد مرفق", `
      <div class="card">
        <h1>لا يوجد مرفق حالي</h1>
        <p>المستخدم <strong>${escapeHtml(targetUser.display_name)}</strong> لم يقم برفع مرفق بعد، أو لا يوجد ملف متاح حالياً.</p>
      </div>
    `));
  }

  if (current.status === "claimed" && current.expires_at && new Date(current.expires_at) <= new Date()) {
    await run(`UPDATE attachments SET status='expired' WHERE id=? AND status='claimed'`, [current.id]);
  }

  const latest = await get(`SELECT * FROM attachments WHERE id=?`, [current.id]);
  if (latest.status === "available") {
    const token = randomToken();
    const now = new Date();
    const expires = new Date(now.getTime() + ACCESS_MINUTES * 60 * 1000);
    const result = await run(`
      UPDATE attachments
      SET status='claimed', claimed_at=?, expires_at=?, claim_token_hash=?
      WHERE id=? AND status='available'
    `, [now.toISOString(), expires.toISOString(), sha256(token), latest.id]);

    if (result.changes === 1) {
      setCookie(res, "qr_access", token, ACCESS_MINUTES * 60, isSecure);
      return res.redirect(`/view?token=${encodeURIComponent(token)}`);
    }
  }

  // If already claimed, check if current visitor has the valid token
  const cookies = parseCookies(req);
  const existingToken = req.query.token || cookies.qr_access;
  if (existingToken) {
    const valid = await get(`
      SELECT * FROM attachments
      WHERE id=? AND status='claimed' AND claim_token_hash=? AND expires_at > ?
    `, [latest.id, sha256(existingToken), new Date().toISOString()]);
    if (valid) {
      setCookie(res, "qr_access", existingToken, ACCESS_MINUTES * 60, isSecure);
      return res.redirect(`/view?token=${encodeURIComponent(existingToken)}`);
    }
  }

  return res.status(410).send(page("المرفق غير متاح", `
    <div class="card">
      <div class="icon">🔒</div>
      <h1>المرفق غير متاح</h1>
      <p>تم استخدام هذا المرفق مسبقًا أو انتهت مدة الوصول (مخصص لمستخدم واحد).</p>
      <p class="muted">عند رفع مرفق جديد من قِبل ${escapeHtml(targetUser.display_name)} سيصبح نفس الباركود صالحًا للاستخدام مرة أخرى.</p>
    </div>
  `));
}

// 1. Default fixed QR route (points to Admin / user 1 - preserves backwards compatibility)
app.get("/q", async (req, res) => {
  let adminUser = await get("SELECT * FROM users WHERE role = 'admin' ORDER BY id ASC LIMIT 1");
  if (!adminUser) {
    adminUser = { id: 1, display_name: "المدير العام", slug: "admin" };
  }
  return handleQrAccess(req, res, adminUser);
});

// 2. User-specific fixed QR route: /q/:slug
app.get("/q/:slug", async (req, res) => {
  const slug = req.params.slug.trim().toLowerCase();
  const targetUser = await get("SELECT * FROM users WHERE LOWER(slug) = ? OR LOWER(username) = ?", [slug, slug]);
  if (!targetUser) {
    return res.status(404).send(page("المستخدم غير موجود", `
      <div class="card">
        <div class="icon">🔍</div>
        <h1>الرابط غير موجود</h1>
        <p>لا يوجد مستخدم مسجل بهذا الرابط أو الباركود.</p>
      </div>
    `));
  }
  return handleQrAccess(req, res, targetUser);
});

// Viewer page
app.get("/view", async (req, res) => {
  const isSecure = isReqSecure(req);
  const cookies = parseCookies(req);
  const token = req.query.token || cookies.qr_access;
  if (!token) return res.redirect("/q");

  const item = await get(`
    SELECT * FROM attachments
    WHERE status='claimed' AND claim_token_hash=? AND expires_at > ?
    ORDER BY id DESC LIMIT 1
  `, [sha256(token), new Date().toISOString()]);

  if (!item) {
    clearCookie(res, "qr_access", isSecure);
    return res.status(410).send(page("انتهى الوصول", `
      <div class="card"><div class="icon">⏱️</div><h1>انتهت مدة الوصول</h1>
      <p>يرجى انتظار رفع مرفق جديد.</p></div>
    `));
  }

  setCookie(res, "qr_access", token, ACCESS_MINUTES * 60, isSecure);

  const secondsLeft = Math.max(0, Math.floor((new Date(item.expires_at) - new Date()) / 1000));
  const displayName = decodeFilename(item.filename);

  res.send(page("عرض المرفق", `
    <div class="card">
      <div class="topline">
        <span class="badge">🔒 وصول مخصص لشخص واحد</span>
        <div style="display:flex;align-items:center;gap:8px">
          <span class="muted" style="font-size:14px">الوقت المتبقي:</span>
          <span id="timer" style="font-size:20px;font-weight:bold;color:#d92d20;background:#fef3f2;padding:4px 12px;border-radius:10px">${secondsLeft}</span>
        </div>
      </div>

      <h1 style="word-break:break-word;margin:14px 0 6px;font-size:24px">${escapeHtml(displayName)}</h1>
      <p class="muted" style="margin:0 0 16px;font-size:14px">الوقت المتبقي: <strong><span id="count">${secondsLeft}</span> ثانية</strong> &bull; الحجم: <strong>${formatFileSize(item.size)}</strong></p>

      <!-- أزرار التحميل والعرض المباشر للهاتف والكمبيوتر -->
      <div class="action-buttons">
        <a class="button download-btn" href="/file/${item.id}?token=${encodeURIComponent(token)}&download=1" download="${escapeHtml(displayName)}">
          📥 تحميل المرفق (تنزيل)
        </a>
        <a class="button secondary view-full-btn" href="/file/${item.id}?token=${encodeURIComponent(token)}" target="_blank">
          ↗️ فتح في نافذة مستقلة
        </a>
      </div>

      <div class="viewer">
        <iframe src="/file/${item.id}?token=${encodeURIComponent(token)}" title="${escapeHtml(displayName)}"></iframe>
      </div>

      <p class="warning" style="margin-top:16px">⚠️ هذا الوصول مؤقت ومخصص لأول شخص قام بمسح الباركود، وينتهي بانتهاء الوقت المتبقي.</p>
    </div>

    <script>
      let s = ${secondsLeft};
      const c = document.getElementById("count");
      const t = document.getElementById("timer");
      const timer = setInterval(() => {
        s--;
        if (c) c.textContent = Math.max(s,0);
        if (t) t.textContent = Math.max(s,0);
        if (s <= 0) {
          clearInterval(timer);
          location.href = "/q";
        }
      }, 1000);
    </script>
  `));
});

// File delivery
app.get("/file/:id", async (req, res) => {
  const cookies = parseCookies(req);
  const token = req.query.token || cookies.qr_access;
  if (!token) return res.status(403).send("Access denied");

  const item = await get(`
    SELECT * FROM attachments
    WHERE id=? AND status='claimed' AND claim_token_hash=? AND expires_at > ?
  `, [req.params.id, sha256(token), new Date().toISOString()]);

  if (!item) return res.status(403).send("Access denied or expired");

  const full = path.join(UPLOAD_DIR, path.basename(item.stored_name));
  if (!fs.existsSync(full)) return res.status(404).send("File not found");

  const cleanName = decodeFilename(item.filename);
  const isDownload = req.query.download === "1";
  const disposition = isDownload ? "attachment" : "inline";

  res.setHeader("Content-Type", item.mime_type || "application/octet-stream");
  res.setHeader("Content-Disposition", `${disposition}; filename*=UTF-8''${encodeURIComponent(cleanName)}`);
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.sendFile(full);
});

// Dashboard (Admin & User)
app.get("/admin", authMiddleware, async (req, res) => {
  const currentUser = req.user;
  const isAdmin = currentUser.role === "admin";
  const activeTab = (req.query.tab === "users" && isAdmin) ? "users" : "files";

  // Dedicated QR URL for the logged-in user
  const userQrTarget = (currentUser.role === "admin" && currentUser.slug === "admin")
    ? `${BASE_URL}/q`
    : `${BASE_URL}/q/${currentUser.slug}`;

  const qrData = await QRCode.toDataURL(userQrTarget, { width: 360, margin: 2 });

  // Attachments for the current user
  const current = await get(`SELECT * FROM attachments WHERE user_id = ? ORDER BY id DESC LIMIT 1`, [currentUser.id]);
  const history = await all(`SELECT * FROM attachments WHERE user_id = ? ORDER BY id DESC LIMIT 20`, [currentUser.id]);

  const statusText = current
    ? current.status === "available" ? "🟢 جاهز للاستخدام"
      : current.status === "claimed" ? "🔴 مستخدم"
      : "⚫ منتهي"
    : "لا يوجد";

  const currentDisplayFilename = current ? decodeFilename(current.filename) : "";

  // If Admin and on 'users' tab, fetch all users
  let allUsers = [];
  let persistentEnvValue = "";
  if (isAdmin) {
    allUsers = await all(`
      SELECT u.*, 
        (SELECT COUNT(*) FROM attachments a WHERE a.user_id = u.id) AS file_count
      FROM users u ORDER BY u.id ASC
    `);

    const nonAdminUsers = allUsers.filter(u => u.role !== "admin");
    if (nonAdminUsers.length > 0) {
      persistentEnvValue = JSON.stringify(nonAdminUsers.map(u => ({
        username: u.username,
        display_name: u.display_name,
        slug: u.slug,
        password_hash: u.password_hash,
        role: u.role
      })));
    }
  }

  // Flash messages / alerts
  let alertHtml = "";
  if (req.query.msg === "user_created") alertHtml = '<div class="alert-success">✅ تم إنشاء المستخدم بنجاح وتوليد باركوده الخاص.</div>';
  if (req.query.msg === "user_deleted") alertHtml = '<div class="alert-success">🗑️ تم حذف المستخدم ومرفقاته بنجاح.</div>';
  if (req.query.msg === "password_reset") alertHtml = '<div class="alert-success">🔑 تم تغيير كلمة المرور بنجاح.</div>';
  if (req.query.error === "username_exists") alertHtml = '<div class="alert-danger">❌ اسم المستخدم أو الرابط مستخدم مسبقاً، يرجى اختيار اسم آخر.</div>';
  if (req.query.error === "invalid_username") alertHtml = '<div class="alert-danger">❌ اسم المستخدم يجب أن يكون حرفين على الأقل بالإنجليزية والأرقام.</div>';
  if (req.query.error === "reserved_username") alertHtml = '<div class="alert-danger">❌ هذا الاسم محجوز للنظام، اختر اسماً آخر.</div>';
  if (req.query.error === "cannot_delete_admin") alertHtml = '<div class="alert-danger">❌ لا يمكن حذف حساب المدير العام.</div>';

  res.send(page(isAdmin ? "لوحة الإدارة الرئيسية" : "لوحة المرفقات", `
    <!-- Header Bar -->
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;flex-wrap:wrap;gap:12px">
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <div style="font-size:22px;font-weight:bold;color:#1456d9">
          ${escapeHtml(currentUser.display_name)} 
          <span style="font-size:14px;color:#667085;font-weight:normal">(@${escapeHtml(currentUser.username)})</span>
        </div>
        <div class="live-indicator">
          <span class="live-dot"></span> التحديث التلقائي مفعّل
        </div>
      </div>
      <a class="button secondary" href="/admin/logout" style="width:auto;padding:8px 18px;font-size:14px">تسجيل الخروج 🚪</a>
    </div>

    ${alertHtml}

    <!-- Tabs for Admin -->
    ${isAdmin ? `
      <div class="tabs">
        <a href="/admin" class="tab-btn ${activeTab === 'files' ? 'active' : ''}">📄 مرفقاتي والباركود</a>
        <a href="/admin?tab=users" class="tab-btn ${activeTab === 'users' ? 'active' : ''}">👥 إدارة المستخدمين (${allUsers.length})</a>
      </div>
    ` : ""}

    ${activeTab === "users" ? `
      <!-- User Management View -->
      <section class="card" style="margin-bottom:24px">
        <h2>➕ إضافة مستخدم جديد</h2>
        <p class="muted">قم بإنشاء حساب لموظف/مستخدم جديد ليحصل على باركود ورابط مخصص لرفع ملفاته المستقلة.</p>
        <form action="/admin/users/create" method="post" class="add-user-form">
          <div class="form-row">
            <div class="form-group">
              <label>الاسم الكامل (للعرض)</label>
              <input type="text" name="display_name" required placeholder="مثال: سالم الكندي">
            </div>
            <div class="form-group">
              <label>اسم المستخدم / معرف الرابط (بالإنجليزية فقط)</label>
              <input type="text" name="username" required placeholder="مثال: salim" pattern="[a-zA-Z0-9_-]+" title="أحرف إنجليزية وأرقام فقط">
            </div>
            <div class="form-group">
              <label>كلمة المرور</label>
              <input type="password" name="password" required placeholder="••••••••">
            </div>
          </div>
          <button class="button" type="submit" style="width:auto;padding:12px 28px">إنشاء المستخدم وتوليد الباركود ✨</button>
        </form>
      </section>

      <!-- Cloud Persistence Card for Render -->
      <section class="card" style="margin-bottom:24px;border:1.5px solid #b2ccff;background:#f8faff">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
          <span style="font-size:24px">🛡️</span>
          <h2 style="margin:0;font-size:18px;color:#1456d9">حفظ دائم للمستخدمين عند تحديث الخادم (Render)</h2>
        </div>
        <p style="margin:0 0 14px;font-size:13.5px;line-height:1.6;color:#344054">
          يقوم خادم Render بإعادة بناء حاوية النظام ومسح قاعدة البيانات المؤقتة عند كل تحديث برمجي جديد (Redeploy). 
          لضمان بقاء المستخدمين وبطاقات الـ QR الخاصة بهم دائمة 100% دون أن تُحذف، قمنا بتفعيل نظامين تلقائيين للحفظ:
        </p>

        <div style="background:#fff;border:1px solid #d0d5dd;border-radius:12px;padding:14px 16px;margin-bottom:12px">
          <div style="font-weight:bold;margin-bottom:6px;font-size:14px;color:#101828">
            📌 الخيار الأقوى والموصى به: حفظ دائم عبر لوحة Render (Environment)
          </div>
          <p style="font-size:13px;color:#475467;margin:0 0 10px;line-height:1.5">
            إذا قمت بإضافة مستخدمين جدد وتريد ضمان عدم مسحهم في أي تحديث قادم، انسخ القيمة أدناه وضعها لمرة واحدة في <strong>Render Dashboard &rarr; Environment &rarr; Add Environment Variable</strong> باسم <code>PERSISTENT_USERS</code>:
          </p>
          ${persistentEnvValue ? `
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <input type="text" id="persistentUsersVal" readonly value="${escapeHtml(persistentEnvValue)}" style="direction:ltr;font-family:monospace;font-size:12px;flex:1;min-width:240px;padding:10px 12px;background:#f9fafb;border:1px solid #d0d5dd;border-radius:8px">
              <button type="button" class="button" onclick="copyPersistentUsers()" style="margin:0;padding:10px 18px;font-size:13px;white-space:nowrap">📋 نسخ المتغير لـ Render</button>
            </div>
            <div id="copySuccessMsg" style="display:none;color:#027a48;font-size:13px;font-weight:bold;margin-top:8px">✅ تم نسخ المتغير بنجاح! ضعه في Render &rarr; Environment &rarr; PERSISTENT_USERS وسيبقى المستخدمون دائماً.</div>
          ` : `
            <div style="padding:10px 14px;background:#f2f4f7;border-radius:8px;font-size:13px;color:#667085">
              ℹ️ لم تقم بإضافة مستخدمين إضافيين بعد. بمجرد إضافة مستخدم جديد، سيظهر لك هنا كود الحفظ لنسخه إلى Render.
            </div>
          `}
        </div>

        <div style="background:#fff;border:1px solid #d0d5dd;border-radius:12px;padding:12px 16px">
          <div style="font-weight:bold;margin-bottom:4px;font-size:13.5px;color:#101828">
            💾 الحفظ التلقائي عبر الكود (data/users_seed.json)
          </div>
          <p style="font-size:12.5px;color:#475467;margin:0;line-height:1.5">
            يقوم النظام أيضاً تلقائياً بحفظ بيانات أي مستخدم جديد في ملف <code>data/users_seed.json</code> داخل المشروع، وعند رفع أي تحديث جديد إلى Git يتم استرجاع جميع المستخدمين المسجلين تلقائياً عند الإقلاع.
          </p>
        </div>
      </section>

      <section class="card">
        <h2>قائمة المستخدمين والباركودات المخصصة</h2>
        <div class="table-wrap"><table>
          <thead>
            <tr>
              <th>المستخدم</th>
              <th>الصلاحية</th>
              <th>رابط الـ QR الثابت</th>
              <th>الملفات المرفوعة</th>
              <th>تاريخ الإنشاء</th>
              <th>إجراءات</th>
            </tr>
          </thead>
          <tbody>
            ${allUsers.map(u => {
              const uQrUrl = (u.role === 'admin' && u.slug === 'admin') ? `${BASE_URL}/q` : `${BASE_URL}/q/${u.slug}`;
              return `<tr>
                <td><strong>${escapeHtml(u.display_name)}</strong><br><small class="muted">@${escapeHtml(u.username)}</small></td>
                <td><span class="badge" style="${u.role === 'admin' ? 'background:#e0f2fe;color:#0369a1' : ''}">${u.role === 'admin' ? '👑 مدير' : '👤 مستخدم'}</span></td>
                <td>
                  <code style="font-size:12px">${escapeHtml(uQrUrl)}</code>
                  <div style="margin-top:6px;display:flex;gap:6px">
                    <a href="${escapeHtml(uQrUrl)}" target="_blank" class="mini-btn">فتح الرابط</a>
                    <a href="/admin/qr.png?slug=${encodeURIComponent(u.slug)}" download="qr_${escapeHtml(u.slug)}.png" class="mini-btn secondary">تحميل QR</a>
                  </div>
                </td>
                <td><strong>${u.file_count}</strong> مرفق</td>
                <td>${new Date(u.created_at).toLocaleDateString("ar-OM")}</td>
                <td>
                  ${u.role !== 'admin' ? `
                    <div style="display:flex;gap:6px;align-items:center">
                      <form action="/admin/users/reset-password/${u.id}" method="post" onsubmit="return confirmReset(this)" style="display:inline">
                        <input type="hidden" name="new_password" value="">
                        <button type="button" class="mini-btn secondary" onclick="promptReset(this)">تغيير الباسوورد</button>
                      </form>
                      <form action="/admin/users/delete/${u.id}" method="post" onsubmit="return confirm('هل أنت متأكد من حذف المستخدم ${escapeHtml(u.display_name)} وجميع ملفاته نهائياً؟')" style="display:inline">
                        <button type="submit" class="mini-btn danger">حذف 🗑️</button>
                      </form>
                    </div>
                  ` : '<span class="muted">-</span>'}
                </td>
              </tr>`;
            }).join("")}
          </tbody>
        </table></div>
      </section>

      <script>
        function promptReset(btn) {
          const pass = prompt("أدخل كلمة المرور الجديدة للمستخدم:");
          if (pass && pass.trim()) {
            const form = btn.closest("form");
            form.querySelector("input[name='new_password']").value = pass.trim();
            form.submit();
          }
        }
        function copyPersistentUsers() {
          const input = document.getElementById("persistentUsersVal");
          if (!input || !input.value) return;
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(input.value).then(showCopied).catch(fallbackCopy);
          } else {
            fallbackCopy();
          }
          function fallbackCopy() {
            input.select();
            document.execCommand("copy");
            showCopied();
          }
          function showCopied() {
            const msg = document.getElementById("copySuccessMsg");
            if (msg) {
              msg.style.display = "block";
              setTimeout(() => { msg.style.display = "none"; }, 6000);
            }
          }
        }
      </script>
    ` : `
      <!-- Files & Personal QR View -->
      <div class="admin-grid">
        <section class="card">
          <h1>الباركود الثابت الخاص بك</h1>
          <p class="muted">الرابط المخصص لا يتغير: <code>${escapeHtml(userQrTarget)}</code></p>
          <img class="qr" src="${qrData}" alt="QR Code">
          <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
            <a class="button secondary" href="/admin/qr.png" download="my_qr.png">تحميل QR كصورة</a>
            <a class="button secondary" href="${escapeHtml(userQrTarget)}" target="_blank">فتح الرابط للتجربة</a>
          </div>
        </section>

        <section class="card">
          <h1>رفع مرفق جديد</h1>
          <p>رفع ملف جديد يعيد تفعيل الباركود الخاص بك تلقائيًا لمستخدم واحد.</p>
          <form action="/admin/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="attachment" required>
            <button class="button" type="submit">رفع وتفعيل المرفق</button>
          </form>
          <div class="status"><strong>الحالة الحالية:</strong> ${statusText}</div>
          ${current ? `<p><strong>الملف:</strong> ${escapeHtml(currentDisplayFilename)}</p>` : ""}
        </section>
      </div>

      <section class="card">
        <h2>سجل مرفقاتك الأخيرة</h2>
        <div class="table-wrap"><table>
        <tr><th>الملف</th><th>الحالة</th><th>الرفع</th><th>الفتح</th><th>الانتهاء</th></tr>
        ${history.length > 0 ? history.map(x => `<tr>
          <td>${escapeHtml(decodeFilename(x.filename))}</td>
          <td><span class="badge" style="${x.status === 'available' ? 'background:#e9f7ef;color:#18794e' : x.status === 'claimed' ? 'background:#fef3f2;color:#d92d20' : 'background:#f2f4f7;color:#475467'}">${x.status === 'available' ? 'جاهز' : x.status === 'claimed' ? 'مستخدم' : 'منتهي'}</span></td>
          <td>${new Date(x.uploaded_at).toLocaleString("ar-OM")}</td>
          <td>${x.claimed_at ? new Date(x.claimed_at).toLocaleString("ar-OM") : "-"}</td>
          <td>${x.expires_at ? new Date(x.expires_at).toLocaleString("ar-OM") : "-"}</td>
        </tr>`).join("") : '<tr><td colspan="5" class="muted" style="text-align:center">لا توجد مرفقات سابقة</td></tr>'}
        </table></div>
      </section>

      <script>
        let currentStatus = "${current ? current.status : 'none'}";
        let currentId = ${current ? current.id : 0};

        async function checkLiveStatus() {
          try {
            const res = await fetch("/admin/api/status?t=" + Date.now(), { cache: "no-store" });
            if (res.ok) {
              const data = await res.json();
              if (data.status !== currentStatus || data.id !== currentId) {
                try {
                  const ctx = new (window.AudioContext || window.webkitAudioContext)();
                  const osc = ctx.createOscillator();
                  const gain = ctx.createGain();
                  osc.connect(gain);
                  gain.connect(ctx.destination);
                  osc.frequency.setValueAtTime(587.33, ctx.currentTime);
                  osc.frequency.setValueAtTime(880, ctx.currentTime + 0.12);
                  gain.gain.setValueAtTime(0.2, ctx.currentTime);
                  gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.35);
                  osc.start(ctx.currentTime);
                  osc.stop(ctx.currentTime + 0.35);
                } catch (e) {}
                setTimeout(() => location.reload(), 300);
              }
            }
          } catch (e) {}
        }

        setInterval(checkLiveStatus, 2500);
      </script>
    `}
  `));
});

// QR PNG download endpoint
app.get("/admin/qr.png", authMiddleware, async (req, res) => {
  let targetSlug = req.user.slug;
  if (req.user.role === "admin" && req.query.slug) {
    targetSlug = req.query.slug.trim().toLowerCase();
  }
  const qrTarget = (targetSlug === "admin" || !targetSlug) ? `${BASE_URL}/q` : `${BASE_URL}/q/${targetSlug}`;
  const png = await QRCode.toBuffer(qrTarget, { width: 1000, margin: 3 });
  res.type("png").send(png);
});

// Upload attachment
app.post("/admin/upload", authMiddleware, upload.single("attachment"), async (req, res) => {
  if (!req.file) return res.status(400).send("لم يتم اختيار ملف.");
  try {
    let originalname = req.file.originalname;
    try {
      const recovered = Buffer.from(req.file.originalname, "latin1").toString("utf8");
      if (!recovered.includes("\uFFFD")) {
        originalname = recovered;
      }
    } catch {}

    const userId = req.user.id;
    const old = await get(`SELECT * FROM attachments WHERE user_id=? ORDER BY id DESC LIMIT 1`, [userId]);
    if (old) {
      await run(`UPDATE attachments SET status='expired' WHERE user_id=? AND status IN ('available','claimed')`, [userId]);
    }

    await run(`
      INSERT INTO attachments
      (user_id, filename, stored_name, mime_type, size, uploaded_at, status)
      VALUES (?, ?, ?, ?, ?, ?, 'available')
    `, [
      userId,
      originalname,
      req.file.filename,
      req.file.mimetype || "application/octet-stream",
      req.file.size,
      new Date().toISOString()
    ]);

    res.redirect("/admin");
  } catch (e) {
    try { fs.unlinkSync(req.file.path); } catch {}
    console.error(e);
    res.status(500).send("حدث خطأ أثناء حفظ المرفق.");
  }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  if (err.code === "LIMIT_FILE_SIZE") return res.status(413).send("حجم الملف أكبر من الحد المسموح.");
  res.status(500).send("حدث خطأ في الخادم.");
});

app.listen(PORT, async () => {
  console.log(`Server running at ${BASE_URL} (Port: ${PORT})`);
  await syncPersistentUsers();
});

function loginPage(errorMsg = "") {
  return `<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>تسجيل الدخول - نظام مشاركة المستندات</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:Tahoma,Arial,sans-serif;background:#f3f6fb;color:#172033;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.login-card{background:#fff;border-radius:20px;padding:32px 26px;box-shadow:0 10px 30px #17203314;width:100%;max-width:400px}
.login-icon{font-size:44px;text-align:center;margin-bottom:12px}
h1{margin:0 0 8px;font-size:22px;text-align:center;color:#1456d9}
p.sub{text-align:center;color:#667085;margin:0 0 22px;font-size:14px}
.form-group{margin-bottom:18px}
label{display:block;margin-bottom:7px;font-weight:bold;font-size:14px}
input[type=text],input[type=password]{width:100%;padding:13px 15px;border:1.5px solid #d0d5dd;border-radius:12px;font-size:16px;background:#fafafa;transition:border-color .2s}
input[type=text]:focus,input[type=password]:focus{outline:none;border-color:#1456d9;background:#fff}
.pass-wrap{position:relative}
.pass-toggle{position:absolute;left:12px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:18px;color:#667085;padding:4px}
.button{display:block;width:100%;border:0;border-radius:12px;padding:14px;background:#1456d9;color:white;cursor:pointer;font-size:16px;font-weight:bold;margin-top:10px;box-shadow:0 4px 12px rgba(20,86,217,.3)}
.button:hover{opacity:.9}
.error{background:#fee4e2;color:#b42318;padding:12px;border-radius:10px;margin-bottom:18px;font-size:14px;text-align:center}
.hint{margin-top:22px;padding-top:18px;border-top:1px solid #f0f2f5;font-size:13px;color:#667085;line-height:1.6;text-align:center}
.hint code{background:#f0f2f5;padding:2px 6px;border-radius:4px;font-size:12px;direction:ltr;display:inline-block}
</style>
</head>
<body>
  <div class="login-card">
    <div class="login-icon">🔐</div>
    <h1>تسجيل الدخول للنظام</h1>
    <p class="sub">أدخل بيانات حسابك للوصول إلى لوحة المرفقات والباركود</p>
    ${errorMsg ? `<div class="error">${escapeHtml(errorMsg)}</div>` : ""}
    <form action="/admin/login" method="post">
      <div class="form-group">
        <label for="username">اسم المستخدم</label>
        <input type="text" id="username" name="username" required autofocus autocapitalize="none" autocomplete="username" placeholder="اسم المستخدم">
      </div>
      <div class="form-group">
        <label for="password">كلمة المرور</label>
        <div class="pass-wrap">
          <input type="password" id="password" name="password" required autocomplete="current-password" placeholder="••••••••">
          <button type="button" class="pass-toggle" onclick="togglePass()" title="إظهار / إخفاء">👁️</button>
        </div>
      </div>
      <button type="submit" class="button">تسجيل الدخول</button>
    </form>
    //<div class="hint">
     // حساب المدير العام: <code>admin</code><br>
    //  كلمة المرور: <code>Admin123</code> أو <code>ChangeThisPasswordNow</code>
    </div>
  </div>
  <script>
    function togglePass() {
      const p = document.getElementById("password");
      p.type = p.type === "password" ? "text" : "password";
    }
  </script>
</body>
</html>`;
}

function page(title, body) {
  return `<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Tahoma,Arial,sans-serif;background:#f3f6fb;color:#172033}
.wrap{max-width:1150px;margin:0 auto;padding:28px 16px}
.card{background:#fff;border-radius:20px;padding:26px;box-shadow:0 10px 30px #17203314;margin-bottom:18px}
h1{margin-top:0;font-size:26px}h2{font-size:20px;margin-top:0}.muted{color:#667085}.icon{font-size:45px}
.admin-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.qr{display:block;width:min(340px,100%);margin:20px auto;border:1px solid #eaecf0;border-radius:16px;padding:8px}
input[type=file]{width:100%;padding:15px;border:1px solid #d0d5dd;border-radius:12px;margin:15px 0}
.button{display:inline-block;border:0;border-radius:12px;padding:13px 18px;background:#1456d9;color:white;text-decoration:none;cursor:pointer;font-size:15px;font-weight:bold}
.button.secondary{background:#eef4ff;color:#1456d9}
.status{margin-top:18px;padding:14px;background:#f7f9fc;border-radius:12px}
.badge{display:inline-block;padding:5px 10px;background:#e9f7ef;border-radius:20px;color:#18794e;font-size:13px;font-weight:bold}
.live-indicator{display:inline-flex;align-items:center;gap:8px;font-size:13px;color:#18794e;background:#e9f7ef;padding:6px 14px;border-radius:20px;font-weight:bold}
.live-dot{width:9px;height:9px;background-color:#18794e;border-radius:50%;display:inline-block;animation:pulse 1.8s infinite}
@keyframes pulse{0%{transform:scale(0.9);box-shadow:0 0 0 0 rgba(24,121,78,0.7)}70%{transform:scale(1);box-shadow:0 0 0 7px rgba(24,121,78,0)}100%{transform:scale(0.9);box-shadow:0 0 0 0 rgba(24,121,78,0)}}
.topline{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
#timer{font-size:22px;font-weight:bold}
.action-buttons{display:flex;gap:12px;margin:16px 0 20px;flex-wrap:wrap}
.download-btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;background:#1456d9;color:#fff;font-weight:bold;padding:13px 22px;border-radius:12px;text-decoration:none;font-size:15px;box-shadow:0 4px 12px rgba(20,86,217,.25);width:auto}
.download-btn:hover{background:#0e46b8}
.view-full-btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;width:auto;padding:13px 20px;font-size:15px}
.viewer{border:1px solid #e1e5eb;border-radius:14px;overflow:hidden;background:#fff}
.viewer iframe{display:block;width:100%;height:70vh;min-height:500px;border:0}
.warning{padding:12px;border-radius:10px;background:#fff8e6;color:#7a5b00}
.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse}th,td{padding:12px;border-bottom:1px solid #eee;text-align:right;white-space:nowrap}
th{background:#f8fafc;color:#475467;font-weight:600}
code{background:#f0f2f5;padding:3px 6px;border-radius:5px;direction:ltr;display:inline-block;font-family:monospace}
.tabs{display:flex;gap:10px;margin-bottom:20px;border-bottom:2px solid #eaecf0;padding-bottom:12px}
.tab-btn{padding:10px 22px;border-radius:10px;text-decoration:none;color:#475467;font-weight:bold;font-size:15px;background:#fff;border:1px solid #d0d5dd;transition:all .2s}
.tab-btn.active{background:#1456d9;color:#fff;border-color:#1456d9;box-shadow:0 4px 12px rgba(20,86,217,.2)}
.form-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;margin-bottom:16px}
.form-group{margin-bottom:12px}
.form-group label{display:block;margin-bottom:6px;font-weight:bold;font-size:14px}
.form-group input{width:100%;padding:11px 14px;border:1px solid #d0d5dd;border-radius:10px;font-size:15px}
.mini-btn{display:inline-block;padding:5px 10px;border-radius:8px;background:#1456d9;color:#fff;text-decoration:none;font-size:12px;font-weight:bold;border:none;cursor:pointer}
.mini-btn.secondary{background:#eef4ff;color:#1456d9}
.mini-btn.danger{background:#fee4e2;color:#b42318}
.alert-success{background:#ecfdf3;color:#027a48;border:1px solid #a6f4c5;padding:12px 16px;border-radius:12px;margin-bottom:18px;font-weight:bold}
.alert-danger{background:#fef3f2;color:#b42318;border:1px solid #fecdca;padding:12px 16px;border-radius:12px;margin-bottom:18px;font-weight:bold}
@media(max-width:750px){.admin-grid{grid-template-columns:1fr}.card{padding:20px}.viewer iframe{min-height:420px;height:60vh}}
@media(max-width:650px){.action-buttons{flex-direction:column}.download-btn,.view-full-btn{width:100%;text-align:center}}
</style>
</head>
<body><main class="wrap">${body}</main></body></html>`;
}
