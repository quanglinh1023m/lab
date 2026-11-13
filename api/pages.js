const {
  getSupabaseClient,
  verifyAdminSecret,
  SLUG_REGEX,
  RESERVED_SLUGS,
} = require("./save");

function extractAdminSecret(req) {
  const headerSecret = req.headers?.["x-admin-secret"];
  if (typeof headerSecret === "string" && headerSecret.length > 0) {
    return headerSecret;
  }
  const auth = req.headers?.authorization;
  if (typeof auth === "string" && auth.toLowerCase().startsWith("bearer ")) {
    return auth.slice(7).trim();
  }
  return "";
}

function createPagesHandler(deps = {}) {
  const getClient = deps.getSupabaseClient || getSupabaseClient;
  const getAdminSecret = deps.getAdminSecret || (() => process.env.ADMIN_SECRET);

  return async function handler(req, res) {
    res.setHeader("Cache-Control", "no-store, max-age=0");

    if (req.method !== "GET" && req.method !== "DELETE") {
      return res.status(405).json({ error: "Method not allowed." });
    }

    try {
      const expectedAdminSecret = getAdminSecret();
      if (!expectedAdminSecret || !String(expectedAdminSecret).trim()) {
        console.error(JSON.stringify({ event: "pages_missing_admin_secret" }));
        return res.status(500).json({ error: "Máy chủ chưa cấu hình ADMIN_SECRET." });
      }

      const providedSecret = extractAdminSecret(req);
      if (!verifyAdminSecret(providedSecret, String(expectedAdminSecret))) {
        return res.status(401).json({ error: "Mật khẩu Admin không chính xác." });
      }

      const supabase = getClient();

      if (req.method === "GET") {
        const { data, error } = await supabase
          .from("pages")
          .select("slug, created_at, updated_at")
          .order("updated_at", { ascending: false });

        if (error) {
          console.error(JSON.stringify({ event: "pages_list_error", message: error.message }));
          return res.status(500).json({ error: "Không thể tải danh sách trang." });
        }

        return res.status(200).json({ pages: data || [] });
      }

      let body = req.body || {};
      if (typeof body === "string") {
        try {
          body = JSON.parse(body);
        } catch {
          return res.status(400).json({ error: "Dữ liệu JSON không hợp lệ." });
        }
      }

      const rawSlug =
        typeof req.query?.slug === "string"
          ? req.query.slug
          : typeof body.slug === "string"
            ? body.slug
            : "";
      const slug = rawSlug.trim().toLowerCase();

      if (!slug || !SLUG_REGEX.test(slug) || RESERVED_SLUGS.has(slug)) {
        return res.status(400).json({ error: "Tên đường dẫn (slug) không hợp lệ." });
      }

      const { data: deletedRow, error: deleteError } = await supabase
        .from("pages")
        .delete()
        .eq("slug", slug)
        .select("slug")
        .maybeSingle();

      if (deleteError) {
        console.error(JSON.stringify({ event: "pages_delete_error", slug, message: deleteError.message }));
        return res.status(500).json({ error: "Không thể xóa trang." });
      }

      if (!deletedRow) {
        return res.status(404).json({ error: "Không tìm thấy trang cần xóa." });
      }

      return res.status(200).json({ deleted: true, slug });
    } catch (err) {
      console.error(JSON.stringify({ event: "pages_unhandled_error", message: err.message }));
      return res.status(500).json({ error: "Lỗi máy chủ nội bộ." });
    }
  };
}

const handler = createPagesHandler();
handler.createPagesHandler = createPagesHandler;

module.exports = handler;

