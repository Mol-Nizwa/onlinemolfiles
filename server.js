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

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Admin123";
const ACCESS_MINUTES = Number(process.env.ACCESS_MINUTES || 5);
const MAX_FILE_MB = Number(process.env.MAX_FILE_MB || 50);

const UPLOAD_DIR = path.join(ROOT, "uploads");
const DATA_DIR = path.join(ROOT, "data");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new sqlite3.Database(path.join(DATA_DIR, "app.db"));

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS attachments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
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

function setCookie(res, name, value, maxAgeSeconds, isSecure = false) {
  const secureFlag = isSecure ? "; Secure" : "";
  res.setHeader(
    "Set-Cookie",
    `${name}=${encodeURIComponent(value)}; Max-Age=${maxAgeSeconds}; Path=/; HttpOnly; SameSite=Lax${secureFlag}`
  );
}

function clearCookie(res, name, isSecure = false) {
  const secureFlag = isSecure ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${secureFlag}`);
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

function adminAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="QR Admin"');
    return res.status(401).send("Authentication required");
  }
  let decoded = "";
  try {
    decoded = Buffer.from(auth.slice(6), "base64").toString("utf8");
  } catch {
    return res.status(401).send("Invalid authentication");
  }
  const sep = decoded.indexOf(":");
  const user = sep >= 0 ? decoded.slice(0, sep) : "";
  const pass = sep >= 0 ? decoded.slice(sep + 1) : "";
  if (user !== ADMIN_USER || pass !== ADMIN_PASSWORD) {
    res.setHeader("WWW-Authenticate", 'Basic realm="QR Admin"');
    return res.status(401).send("Invalid credentials");
  }
  next();
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

// Fixed QR target. This URL never changes.
app.get("/q", async (req, res) => {
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

  const current = await get(`SELECT * FROM attachments ORDER BY id DESC LIMIT 1`);
  if (!current) return res.send(page("لا يوجد مرفق", `
    <div class="card"><h1>لا يوجد مرفق حالي</h1><p>يرجى رفع مرفق من لوحة الإدارة.</p></div>
  `));

  if (current.status === "claimed" && current.expires_at && new Date(current.expires_at) <= new Date()) {
    await run(`UPDATE attachments SET status='expired' WHERE id=? AND status='claimed'`, [current.id]);
  }

  const latest = await get(`SELECT * FROM attachments WHERE id=?`, [current.id]);
  if (latest.status === "available") {
    const token = randomToken();
    // Claim atomically: only the first request can change available -> claimed.
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
      <p>تم استخدام هذا المرفق مسبقًا أو انتهت مدة الوصول.</p>
      <p class="muted">عند رفع مرفق جديد سيصبح نفس الباركود صالحًا للاستخدام مرة أخرى.</p>
    </div>
  `));
});

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
  res.send(page("عرض المرفق", `
    <div class="card">
      <div class="topline"><span class="badge">وصول مخصص لشخص واحد</span>
      <span id="timer">${secondsLeft}</span></div>
      <h1>${escapeHtml(item.filename)}</h1>
      <p class="muted">الوقت المتبقي: <strong><span id="count">${secondsLeft}</span> ثانية</strong></p>
      <div class="viewer">
        <iframe src="/file/${item.id}?token=${encodeURIComponent(token)}" title="المرفق"></iframe>
      </div>
      <p class="warning">هذا الوصول مؤقت ومخصص لأول مستخدم فتح الباركود.</p>
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

  res.setHeader("Content-Type", item.mime_type || "application/octet-stream");
  res.setHeader("Content-Disposition", `inline; filename*=UTF-8''${encodeURIComponent(item.filename)}`);
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.sendFile(full);
});

app.get("/admin", adminAuth, async (_req, res) => {
  const current = await get(`SELECT * FROM attachments ORDER BY id DESC LIMIT 1`);
  const history = await all(`SELECT * FROM attachments ORDER BY id DESC LIMIT 20`);
  const qrTarget = `${BASE_URL}/q`;
  const qrData = await QRCode.toDataURL(qrTarget, { width: 360, margin: 2 });

  const statusText = current
    ? current.status === "available" ? "🟢 جاهز للاستخدام"
      : current.status === "claimed" ? "🔴 مستخدم"
      : "⚫ منتهي"
    : "لا يوجد";

  res.send(page("لوحة إدارة الباركود", `
    <div class="admin-grid">
      <section class="card">
        <h1>الباركود الثابت</h1>
        <p class="muted">الرابط لا يتغير: <code>${escapeHtml(qrTarget)}</code></p>
        <img class="qr" src="${qrData}" alt="QR Code">
        <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
          <a class="button secondary" href="/admin/qr.png" download="qr.png">تحميل QR كصورة</a>
          <a class="button secondary" href="${escapeHtml(qrTarget)}" target="_blank">فتح الرابط للتجربة</a>
        </div>
      </section>

      <section class="card">
        <h1>رفع مرفق جديد</h1>
        <p>رفع ملف جديد يعيد تفعيل نفس الباركود تلقائيًا.</p>
        <form action="/admin/upload" method="post" enctype="multipart/form-data">
          <input type="file" name="attachment" required>
          <button class="button" type="submit">رفع وتفعيل المرفق</button>
        </form>
        <div class="status"><strong>الحالة الحالية:</strong> ${statusText}</div>
        ${current ? `<p><strong>الملف:</strong> ${escapeHtml(current.filename)}</p>` : ""}
      </section>
    </div>

    <section class="card">
      <h2>آخر المرفقات</h2>
      <div class="table-wrap"><table>
      <tr><th>الملف</th><th>الحالة</th><th>الرفع</th><th>الفتح</th><th>الانتهاء</th></tr>
      ${history.map(x => `<tr>
        <td>${escapeHtml(x.filename)}</td>
        <td>${x.status}</td>
        <td>${new Date(x.uploaded_at).toLocaleString("ar-OM")}</td>
        <td>${x.claimed_at ? new Date(x.claimed_at).toLocaleString("ar-OM") : "-"}</td>
        <td>${x.expires_at ? new Date(x.expires_at).toLocaleString("ar-OM") : "-"}</td>
      </tr>`).join("")}
      </table></div>
    </section>
  `));
});

app.get("/admin/qr.png", adminAuth, async (_req, res) => {
  const qrTarget = `${BASE_URL}/q`;
  const png = await QRCode.toBuffer(qrTarget, { width: 1000, margin: 3 });
  res.type("png").send(png);
});

app.post("/admin/upload", adminAuth, upload.single("attachment"), async (req, res) => {
  if (!req.file) return res.status(400).send("لم يتم اختيار ملف.");
  try {
    const old = await get(`SELECT * FROM attachments ORDER BY id DESC LIMIT 1`);
    // Make previous cycle unavailable immediately.
    if (old) {
      await run(`UPDATE attachments SET status='expired' WHERE status IN ('available','claimed')`);
    }

    await run(`
      INSERT INTO attachments
      (filename, stored_name, mime_type, size, uploaded_at, status)
      VALUES (?, ?, ?, ?, ?, 'available')
    `, [
      req.file.originalname,
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

app.listen(PORT, () => {
  console.log(`Server running at ${BASE_URL} (Port: ${PORT})`);
});

function page(title, body) {
  return `<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Tahoma,Arial,sans-serif;background:#f3f6fb;color:#172033}
.wrap{max-width:1100px;margin:0 auto;padding:28px 16px}
.card{background:#fff;border-radius:20px;padding:26px;box-shadow:0 10px 30px #17203314;margin-bottom:18px}
h1{margin-top:0;font-size:28px}h2{font-size:21px}.muted{color:#667085}.icon{font-size:45px}
.admin-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.qr{display:block;width:min(360px,100%);margin:20px auto}
input[type=file]{width:100%;padding:15px;border:1px solid #d0d5dd;border-radius:12px;margin:15px 0}
.button{display:inline-block;border:0;border-radius:12px;padding:13px 18px;background:#1456d9;color:white;text-decoration:none;cursor:pointer;font-size:15px}
.button.secondary{background:#eef4ff;color:#1456d9}
.status{margin-top:18px;padding:14px;background:#f7f9fc;border-radius:12px}
.badge{display:inline-block;padding:7px 10px;background:#e9f7ef;border-radius:20px;color:#18794e}
.topline{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
#timer{font-size:22px;font-weight:bold}
.viewer{border:1px solid #e1e5eb;border-radius:14px;overflow:hidden;background:#fff}
.viewer iframe{display:block;width:100%;height:70vh;min-height:500px;border:0}
.warning{padding:12px;border-radius:10px;background:#fff8e6;color:#7a5b00}
.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse}th,td{padding:11px;border-bottom:1px solid #eee;text-align:right;white-space:nowrap}
code{background:#f0f2f5;padding:3px 6px;border-radius:5px;direction:ltr;display:inline-block}
@media(max-width:750px){.admin-grid{grid-template-columns:1fr}.card{padding:20px}.viewer iframe{min-height:420px;height:60vh}}
</style>
</head>
<body><main class="wrap">${body}</main></body></html>`;
}
