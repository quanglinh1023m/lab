const { createClient } = require("@supabase/supabase-js");

const DB_TIMEOUT_MS = 10000;
const SLUG_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

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

function createViewHandler(deps = {}) {
  const getClient = deps.getSupabaseClient || getSupabaseClient;

  return async function handler(req, res) {
    if (req.method !== "GET") {
      return res.status(405).send("Method Not Allowed");
    }

    const slug = String(req.query?.slug || "").trim().toLowerCase();
    if (!slug || !SLUG_REGEX.test(slug)) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(400).send("<h1>400 - Đường dẫn không hợp lệ</h1>");
    }

    try {
      const supabase = getClient();
      const { data, error } = await supabase
        .from("pages")
        .select("html_content")
        .eq("slug", slug)
        .maybeSingle();

      if (error) {
        console.error(JSON.stringify({ event: "view_query_error", slug, message: error.message }));
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.status(500).send("<h1>500 - Không thể tải trang</h1>");
      }

      if (!data) {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.status(404).send("<h1>404 - Trang không tồn tại</h1>");
      }

      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Cache-Control", "no-store, max-age=0");
      res.setHeader("X-Content-Type-Options", "nosniff");
      return res.status(200).send(data.html_content);
    } catch (err) {
      console.error(JSON.stringify({ event: "view_unhandled_error", slug, message: err.message }));
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(500).send("<h1>500 - Lỗi máy chủ</h1>");
    }
  };
}

const handler = createViewHandler();
handler.createViewHandler = createViewHandler;
handler.SLUG_REGEX = SLUG_REGEX;

module.exports = handler;

