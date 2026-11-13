const crypto = require("node:crypto");
const { createClient } = require("@supabase/supabase-js");

const MAX_HTML_BYTES = 2 * 1024 * 1024; // 2 MB safety cap below Vercel's 4.5 MB limit
const DB_TIMEOUT_MS = 10000;
const MAX_PIN_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes
const RESERVED_SLUGS = new Set(["api", "editor"]);
const SLUG_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const PIN_REGEX = /^\d{4,6}$/;

function getSupabaseClient() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_KEY;
  if (!url || !key) {
    throw new Error("Missing SUPABASE_URL or SUPABASE_KEY environment variable.");
  }
  return createClient(url, key, {
    global: {
      fetch: (input, init = {}) =>
        fetch(input, {
          ...init,
          signal: init.signal || AbortSignal.timeout(DB_TIMEOUT_MS),
        }),
    },
  });
}

function hashPin(pin) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(pin, salt, 32).toString("hex");
  return `${salt}:${derived}`;
}

function verifyPin(pin, storedValue) {
  const parts = String(storedValue || "").split(":");
  if (parts.length !== 2) return false;
  const [salt, storedHash] = parts;
  if (!salt || !storedHash) return false;
  const derived = crypto.scryptSync(pin, salt, 32);
  const storedBuf = Buffer.from(storedHash, "hex");
  if (derived.length !== storedBuf.length) return false;
  return crypto.timingSafeEqual(derived, storedBuf);
}

function verifyAdminSecret(provided, expected) {
  if (typeof provided !== "string" || typeof expected !== "string") return false;
  if (!provided || !expected) return false;
  const hashProvided = crypto.createHash("sha256").update(provided, "utf8").digest();
  const hashExpected = crypto.createHash("sha256").update(expected, "utf8").digest();
  return crypto.timingSafeEqual(hashProvided, hashExpected);
}

function generateSlug() {
  return crypto.randomBytes(4).toString("hex");
}

function createSaveHandler(deps = {}) {
  const getClient = deps.getSupabaseClient || getSupabaseClient;
  const getAdminSecret = deps.getAdminSecret || (() => process.env.ADMIN_SECRET);
  const nowFn = deps.now || (() => Date.now());

  return async function handler(req, res) {
    res.setHeader("Cache-Control", "no-store, max-age=0");

    if (req.method !== "POST") {
      return res.status(405).json({ error: "Method not allowed." });
    }

    const contentType = req.headers?.["content-type"];
    if (contentType && !String(contentType).toLowerCase().includes("application/json")) {
      return res.status(415).json({ error: "Content-Type phải là application/json." });
    }

    try {
      const expectedAdminSecret = getAdminSecret();
      if (!expectedAdminSecret || !String(expectedAdminSecret).trim()) {
        console.error(JSON.stringify({ event: "save_missing_admin_secret" }));
        return res.status(500).json({ error: "Máy chủ chưa cấu hình ADMIN_SECRET." });
      }

      let body = req.body || {};
      if (typeof body === "string") {
        try {
          body = JSON.parse(body);
        } catch {
          return res.status(400).json({ error: "Dữ liệu JSON không hợp lệ." });
        }
      }

      const providedSecret = typeof body.admin_secret === "string" ? body.admin_secret : "";
      if (!verifyAdminSecret(providedSecret, String(expectedAdminSecret))) {
        return res.status(401).json({ error: "Mật khẩu Admin không chính xác." });
      }

      const mode = body.mode === "edit" ? "edit" : "create";
      const adminOverride = body.admin_override === true;
      const rawSlug = typeof body.slug === "string" ? body.slug.trim().toLowerCase() : "";
      const htmlContent = typeof body.html_content === "string" ? body.html_content : "";
      const editPin = typeof body.edit_pin === "string" ? body.edit_pin.trim() : "";

      if (!htmlContent.trim()) {
        return res.status(400).json({ error: "Nội dung HTML không được để trống." });
      }
      if (Buffer.byteLength(htmlContent, "utf8") > MAX_HTML_BYTES) {
        return res.status(413).json({ error: "Nội dung HTML vượt quá giới hạn 2 MB." });
      }
      if (editPin && !PIN_REGEX.test(editPin)) {
        return res.status(400).json({ error: "Mã PIN phải gồm 4 đến 6 chữ số." });
      }
      if (mode === "edit" && !adminOverride && !editPin) {
        return res.status(400).json({ error: "Mã PIN phải gồm 4 đến 6 chữ số." });
      }

      const slug = rawSlug || (mode === "create" ? generateSlug() : "");
      if (!slug || !SLUG_REGEX.test(slug) || RESERVED_SLUGS.has(slug)) {
        return res.status(400).json({
          error: "Tên đường dẫn (slug) chỉ được chứa chữ thường, số và dấu gạch ngang (1-64 ký tự).",
        });
      }

      const supabase = getClient();

      if (mode === "edit") {
        const { data: existing, error: fetchError } = await supabase
          .from("pages")
          .select("slug, edit_pin, failed_attempts, locked_until")
          .eq("slug", slug)
          .maybeSingle();

        if (fetchError) {
          console.error(JSON.stringify({ event: "save_fetch_error", slug, message: fetchError.message }));
          return res.status(500).json({ error: "Lỗi truy vấn cơ sở dữ liệu." });
        }
        if (!existing) {
          return res.status(404).json({ error: "Không tìm thấy trang cần cập nhật." });
        }

        if (!adminOverride) {
          const now = nowFn();
          const lockedUntilMs = existing.locked_until ? Date.parse(existing.locked_until) : 0;
          if (lockedUntilMs > now) {
            const waitMinutes = Math.ceil((lockedUntilMs - now) / 60000);
            return res.status(429).json({
              error: `Nhập sai PIN quá nhiều lần. Vui lòng thử lại sau ${waitMinutes} phút.`,
            });
          }

          if (!verifyPin(editPin, existing.edit_pin)) {
            const nextAttempts = (Number(existing.failed_attempts) || 0) + 1;
            const isLocked = nextAttempts >= MAX_PIN_ATTEMPTS;
            const lockPatch = isLocked
              ? { failed_attempts: nextAttempts, locked_until: new Date(now + LOCKOUT_MS).toISOString() }
              : { failed_attempts: nextAttempts };

            const { error: lockUpdateError } = await supabase
              .from("pages")
              .update(lockPatch)
              .eq("slug", slug);

            if (lockUpdateError) {
              console.error(JSON.stringify({ event: "save_lock_update_error", slug, message: lockUpdateError.message }));
            }

            if (isLocked) {
              return res.status(429).json({
                error: "Nhập sai PIN 5 lần liên tiếp. Đã tạm khóa sửa trang trong 15 phút.",
              });
            }

            return res.status(403).json({
              error: `Mã PIN không chính xác. Còn ${MAX_PIN_ATTEMPTS - nextAttempts} lần thử.`,
            });
          }
        }

        const updatePayload = { html_content: htmlContent, failed_attempts: 0, locked_until: null };
        if (adminOverride && editPin) {
          updatePayload.edit_pin = hashPin(editPin);
        }

        const { error: updateError } = await supabase
          .from("pages")
          .update(updatePayload)
          .eq("slug", slug);

        if (updateError) {
          console.error(JSON.stringify({ event: "save_update_error", slug, message: updateError.message }));
          return res.status(500).json({ error: "Không thể cập nhật nội dung." });
        }

        return res.status(200).json({ slug, updated: true });
      }

      const { data: existingSlug, error: checkError } = await supabase
        .from("pages")
        .select("slug")
        .eq("slug", slug)
        .maybeSingle();

      if (checkError) {
        console.error(JSON.stringify({ event: "save_check_error", slug, message: checkError.message }));
        return res.status(500).json({ error: "Lỗi kiểm tra đường dẫn." });
      }
      if (existingSlug) {
        return res.status(409).json({
          error: "Đường dẫn này đã tồn tại. Vui lòng chọn tên khác hoặc dùng link sửa.",
        });
      }

      const effectivePin = editPin || String(crypto.randomInt(100000, 1000000));
      const { error: insertError } = await supabase.from("pages").insert({
        slug,
        html_content: htmlContent,
        edit_pin: hashPin(effectivePin),
      });

      if (insertError) {
        if (insertError.code === "23505") {
          return res.status(409).json({
            error: "Đường dẫn này đã tồn tại. Vui lòng chọn tên khác hoặc dùng link sửa.",
          });
        }
        console.error(JSON.stringify({ event: "save_insert_error", slug, message: insertError.message }));
        return res.status(500).json({ error: "Không thể lưu trang mới." });
      }

      return res.status(201).json({ slug, updated: false });
    } catch (err) {
      console.error(JSON.stringify({ event: "save_unhandled_error", message: err.message }));
      return res.status(500).json({ error: "Lỗi máy chủ nội bộ." });
    }
  };
}

const handler = createSaveHandler();
handler.createSaveHandler = createSaveHandler;
handler.getSupabaseClient = getSupabaseClient;
handler.hashPin = hashPin;
handler.verifyPin = verifyPin;
handler.verifyAdminSecret = verifyAdminSecret;
handler.MAX_HTML_BYTES = MAX_HTML_BYTES;
handler.MAX_PIN_ATTEMPTS = MAX_PIN_ATTEMPTS;
handler.SLUG_REGEX = SLUG_REGEX;
handler.PIN_REGEX = PIN_REGEX;
handler.RESERVED_SLUGS = RESERVED_SLUGS;

module.exports = handler;

