const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const saveHandler = require("../api/save");
const viewHandler = require("../api/view");

function createMockRes() {
  const headers = {};
  const res = {
    statusCode: 200,
    headers,
    body: undefined,
    setHeader(name, value) {
      headers[name.toLowerCase()] = value;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
    send(payload) {
      this.body = payload;
      return this;
    },
  };
  return res;
}

function createMockSupabase(initialRows = [], options = {}) {
  const store = new Map(initialRows.map((row) => [row.slug, { ...row }]));

  return {
    store,
    from(table) {
      assert.equal(table, "pages");
      return {
        select() {
          return {
            eq(col, val) {
              assert.equal(col, "slug");
              return {
                async maybeSingle() {
                  if (options.selectError) {
                    return { data: null, error: { message: options.selectError } };
                  }
                  const row = store.get(val) || null;
                  return { data: row ? { ...row } : null, error: null };
                },
              };
            },
          };
        },
        async insert(row) {
          if (options.insertError) {
            return { error: { message: options.insertError } };
          }
          store.set(row.slug, { ...row });
          return { error: null };
        },
        update(patch) {
          return {
            async eq(col, val) {
              assert.equal(col, "slug");
              if (options.updateError) {
                return { error: { message: options.updateError } };
              }
              const existing = store.get(val);
              if (existing) {
                store.set(val, { ...existing, ...patch });
              }
              return { error: null };
            },
          };
        },
      };
    },
  };
}

describe("PIN hashing utilities", () => {
  it("hashes and verifies matching PIN while rejecting wrong PINs", () => {
    const hashed = saveHandler.hashPin("4829");
    assert.ok(hashed.includes(":"));
    assert.notEqual(hashed, "4829");
    assert.equal(saveHandler.verifyPin("4829", hashed), true);
    assert.equal(saveHandler.verifyPin("9999", hashed), false);
    assert.equal(saveHandler.verifyPin("4829", "invalid-format"), false);
  });
});

describe("api/save handler", () => {
  it("rejects non-POST requests with 405", async () => {
    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => createMockSupabase(),
    });
    const res = createMockRes();
    await handler({ method: "GET" }, res);
    assert.equal(res.statusCode, 405);
  });

  it("validates empty HTML, invalid PIN, reserved/invalid slug, and malformed JSON", async () => {
    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => createMockSupabase(),
    });

    const badJsonRes = createMockRes();
    await handler({ method: "POST", body: "{not-json" }, badJsonRes);
    assert.equal(badJsonRes.statusCode, 400);

    const emptyHtmlRes = createMockRes();
    await handler({ method: "POST", body: { html_content: "   ", edit_pin: "1234" } }, emptyHtmlRes);
    assert.equal(emptyHtmlRes.statusCode, 400);

    const badPinRes = createMockRes();
    await handler({ method: "POST", body: { html_content: "<h1>Hi</h1>", edit_pin: "12a4" } }, badPinRes);
    assert.equal(badPinRes.statusCode, 400);

    const reservedApiRes = createMockRes();
    await handler({ method: "POST", body: { slug: "api", html_content: "<h1>Hi</h1>", edit_pin: "1234" } }, reservedApiRes);
    assert.equal(reservedApiRes.statusCode, 400);

    const reservedEditorRes = createMockRes();
    await handler({ method: "POST", body: { slug: "editor", html_content: "<h1>Hi</h1>", edit_pin: "1234" } }, reservedEditorRes);
    assert.equal(reservedEditorRes.statusCode, 400);

    const badCharSlugRes = createMockRes();
    await handler({ method: "POST", body: { slug: "a b", html_content: "<h1>Hi</h1>", edit_pin: "1234" } }, badCharSlugRes);
    assert.equal(badCharSlugRes.statusCode, 400);
  });

  it("rejects HTML payloads exceeding 2 MB with 413", async () => {
    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => createMockSupabase(),
    });
    const res = createMockRes();
    const oversized = "a".repeat(saveHandler.MAX_HTML_BYTES + 1);
    await handler({ method: "POST", body: { html_content: oversized, edit_pin: "1234" } }, res);
    assert.equal(res.statusCode, 413);
  });

  it("creates a new page with custom slug and hashed PIN", async () => {
    const mockDb = createMockSupabase();
    const handler = saveHandler.createSaveHandler({ getSupabaseClient: () => mockDb });
    const res = createMockRes();

    await handler(
      {
        method: "POST",
        body: { slug: "Demo-Page", html_content: "<h1>Hello</h1>", edit_pin: "123456" },
      },
      res
    );

    assert.equal(res.statusCode, 201);
    assert.deepEqual(res.body, { slug: "demo-page", updated: false });
    const saved = mockDb.store.get("demo-page");
    assert.ok(saved);
    assert.equal(saved.html_content, "<h1>Hello</h1>");
    assert.equal(saveHandler.verifyPin("123456", saved.edit_pin), true);
  });

  it("creates a new page with alphanumeric slug without hyphens", async () => {
    const mockDb = createMockSupabase();
    const handler = saveHandler.createSaveHandler({ getSupabaseClient: () => mockDb });
    const res = createMockRes();

    await handler(
      {
        method: "POST",
        body: { slug: "trangmoi2026", html_content: "<h1>No Hyphen</h1>", edit_pin: "1234" },
      },
      res
    );

    assert.equal(res.statusCode, 201);
    assert.deepEqual(res.body, { slug: "trangmoi2026", updated: false });
    assert.equal(mockDb.store.get("trangmoi2026").html_content, "<h1>No Hyphen</h1>");
  });

  it("allows 1-character slugs and 'index' slug", async () => {
    const mockDb = createMockSupabase();
    const save = saveHandler.createSaveHandler({ getSupabaseClient: () => mockDb });
    const view = viewHandler.createViewHandler({ getSupabaseClient: () => mockDb });

    const saveOneRes = createMockRes();
    await save({ method: "POST", body: { slug: "1", html_content: "<h1>One</h1>", edit_pin: "1234" } }, saveOneRes);
    assert.equal(saveOneRes.statusCode, 201);
    assert.equal(saveOneRes.body.slug, "1");

    const viewOneRes = createMockRes();
    await view({ method: "GET", query: { slug: "1" } }, viewOneRes);
    assert.equal(viewOneRes.statusCode, 200);
    assert.equal(viewOneRes.body, "<h1>One</h1>");

    const saveIndexRes = createMockRes();
    await save({ method: "POST", body: { slug: "index", html_content: "<h1>Index Slug</h1>", edit_pin: "1234" } }, saveIndexRes);
    assert.equal(saveIndexRes.statusCode, 201);
    assert.equal(saveIndexRes.body.slug, "index");

    const viewIndexRes = createMockRes();
    await view({ method: "GET", query: { slug: "index" } }, viewIndexRes);
    assert.equal(viewIndexRes.statusCode, 200);
    assert.equal(viewIndexRes.body, "<h1>Index Slug</h1>");
  });

  it("auto-generates a valid slug when omitted", async () => {
    const mockDb = createMockSupabase();
    const handler = saveHandler.createSaveHandler({ getSupabaseClient: () => mockDb });
    const res = createMockRes();

    await handler({ method: "POST", body: { html_content: "<p>Auto</p>", edit_pin: "4321" } }, res);

    assert.equal(res.statusCode, 201);
    assert.match(res.body.slug, /^[a-f0-9]{8}$/);
    assert.equal(mockDb.store.has(res.body.slug), true);
  });

  it("returns 409 when creating with an already-existing slug", async () => {
    const mockDb = createMockSupabase([
      { slug: "taken", html_content: "<p>Old</p>", edit_pin: saveHandler.hashPin("1234") },
    ]);
    const handler = saveHandler.createSaveHandler({ getSupabaseClient: () => mockDb });
    const res = createMockRes();

    await handler(
      { method: "POST", body: { slug: "taken", html_content: "<p>New</p>", edit_pin: "1234" } },
      res
    );

    assert.equal(res.statusCode, 409);
    assert.equal(mockDb.store.get("taken").html_content, "<p>Old</p>");
  });

  it("updates an existing page only when PIN matches and returns 403/404 otherwise", async () => {
    const mockDb = createMockSupabase([
      { slug: "my-site", html_content: "<h1>V1</h1>", edit_pin: saveHandler.hashPin("7788") },
    ]);
    const handler = saveHandler.createSaveHandler({ getSupabaseClient: () => mockDb });

    const wrongPinRes = createMockRes();
    await handler(
      { method: "POST", body: { mode: "edit", slug: "my-site", html_content: "<h1>V2</h1>", edit_pin: "0000" } },
      wrongPinRes
    );
    assert.equal(wrongPinRes.statusCode, 403);
    assert.equal(mockDb.store.get("my-site").html_content, "<h1>V1</h1>");

    const missingRes = createMockRes();
    await handler(
      { method: "POST", body: { mode: "edit", slug: "unknown", html_content: "<h1>V2</h1>", edit_pin: "7788" } },
      missingRes
    );
    assert.equal(missingRes.statusCode, 404);

    const okRes = createMockRes();
    await handler(
      { method: "POST", body: { mode: "edit", slug: "my-site", html_content: "<h1>V2</h1>", edit_pin: "7788" } },
      okRes
    );
    assert.equal(okRes.statusCode, 200);
    assert.deepEqual(okRes.body, { slug: "my-site", updated: true });
    assert.equal(mockDb.store.get("my-site").html_content, "<h1>V2</h1>");
  });

  it("returns 500 when Supabase reports a database error", async () => {
    const mockDb = createMockSupabase([], { insertError: "DB down" });
    const handler = saveHandler.createSaveHandler({ getSupabaseClient: () => mockDb });
    const res = createMockRes();

    await handler(
      { method: "POST", body: { slug: "ok-slug", html_content: "<p>Hi</p>", edit_pin: "1234" } },
      res
    );

    assert.equal(res.statusCode, 500);
  });
});

describe("api/view handler", () => {
  it("rejects non-GET requests with 405", async () => {
    const handler = viewHandler.createViewHandler({
      getSupabaseClient: () => createMockSupabase(),
    });
    const res = createMockRes();
    await handler({ method: "POST", query: { slug: "demo" } }, res);
    assert.equal(res.statusCode, 405);
  });

  it("returns 400 for invalid or missing slug", async () => {
    const handler = viewHandler.createViewHandler({
      getSupabaseClient: () => createMockSupabase(),
    });
    const res = createMockRes();
    await handler({ method: "GET", query: { slug: "!" } }, res);
    assert.equal(res.statusCode, 400);
  });

  it("returns 404 when page is not found", async () => {
    const handler = viewHandler.createViewHandler({
      getSupabaseClient: () => createMockSupabase(),
    });
    const res = createMockRes();
    await handler({ method: "GET", query: { slug: "missing-page" } }, res);
    assert.equal(res.statusCode, 404);
    assert.equal(res.headers["content-type"], "text/html; charset=utf-8");
  });

  it("returns 200 with HTML content and proper headers", async () => {
    const mockDb = createMockSupabase([
      { slug: "live-page", html_content: "<!DOCTYPE html><h1>Live</h1>", edit_pin: "hash" },
    ]);
    const handler = viewHandler.createViewHandler({ getSupabaseClient: () => mockDb });
    const res = createMockRes();

    await handler({ method: "GET", query: { slug: "live-page" } }, res);

    assert.equal(res.statusCode, 200);
    assert.equal(res.headers["content-type"], "text/html; charset=utf-8");
    assert.equal(res.headers["cache-control"], "no-store, max-age=0");
    assert.equal(res.headers["x-content-type-options"], "nosniff");
    assert.equal(res.body, "<!DOCTYPE html><h1>Live</h1>");
  });

  it("returns 500 when Supabase query fails", async () => {
    const mockDb = createMockSupabase([], { selectError: "timeout" });
    const handler = viewHandler.createViewHandler({ getSupabaseClient: () => mockDb });
    const res = createMockRes();

    await handler({ method: "GET", query: { slug: "any-slug" } }, res);
    assert.equal(res.statusCode, 500);
  });
});

