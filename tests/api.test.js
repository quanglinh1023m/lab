const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const saveHandler = require("../api/save");
const viewHandler = require("../api/view");
const pagesHandler = require("../api/pages");

const TEST_ADMIN_SECRET = "test-admin-secret-999";

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
  const store = new Map(
    initialRows.map((row) => [
      row.slug,
      { failed_attempts: 0, locked_until: null, ...row },
    ])
  );

  return {
    store,
    from(table) {
      assert.equal(table, "pages");
      return {
        select() {
          return {
            async order() {
              if (options.selectError) {
                return { data: null, error: { message: options.selectError } };
              }
              return {
                data: Array.from(store.values()).map((row) => ({ ...row })),
                error: null,
              };
            },
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
        delete() {
          return {
            eq(col, val) {
              assert.equal(col, "slug");
              return {
                select() {
                  return {
                    async maybeSingle() {
                      if (options.deleteError) {
                        return { data: null, error: { message: options.deleteError } };
                      }
                      const existing = store.get(val);
                      if (!existing) {
                        return { data: null, error: null };
                      }
                      store.delete(val);
                      return { data: { slug: val }, error: null };
                    },
                  };
                },
              };
            },
          };
        },
        async insert(row) {
          if (options.insertError || options.insertErrorCode) {
            return {
              error: {
                message: options.insertError || "Insert failed",
                code: options.insertErrorCode,
              },
            };
          }
          store.set(row.slug, { failed_attempts: 0, locked_until: null, ...row });
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

describe("PIN hashing & Admin secret utilities", () => {
  it("hashes and verifies matching PIN while rejecting wrong PINs", () => {
    const hashed = saveHandler.hashPin("4829");
    assert.ok(hashed.includes(":"));
    assert.notEqual(hashed, "4829");
    assert.equal(saveHandler.verifyPin("4829", hashed), true);
    assert.equal(saveHandler.verifyPin("9999", hashed), false);
    assert.equal(saveHandler.verifyPin("4829", "invalid-format"), false);
  });

  it("verifies admin secret with constant-time comparison", () => {
    assert.equal(saveHandler.verifyAdminSecret("abc", "abc"), true);
    assert.equal(saveHandler.verifyAdminSecret("abc", "abcd"), false);
    assert.equal(saveHandler.verifyAdminSecret("", "abc"), false);
  });
});

describe("api/save handler", () => {
  it("rejects non-POST requests with 405 and non-JSON Content-Type with 415", async () => {
    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => createMockSupabase(),
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });

    const getRes = createMockRes();
    await handler({ method: "GET" }, getRes);
    assert.equal(getRes.statusCode, 405);
    assert.equal(getRes.headers["cache-control"], "no-store, max-age=0");

    const xmlRes = createMockRes();
    await handler(
      { method: "POST", headers: { "content-type": "text/plain" }, body: {} },
      xmlRes
    );
    assert.equal(xmlRes.statusCode, 415);
  });

  it("fails closed with 500 when ADMIN_SECRET is missing and 401 on wrong admin secret", async () => {
    const noSecretHandler = saveHandler.createSaveHandler({
      getSupabaseClient: () => createMockSupabase(),
      getAdminSecret: () => "",
    });
    const noSecretRes = createMockRes();
    await noSecretHandler(
      { method: "POST", body: { admin_secret: "any", html_content: "<h1>Hi</h1>", edit_pin: "1234" } },
      noSecretRes
    );
    assert.equal(noSecretRes.statusCode, 500);

    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => createMockSupabase(),
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });
    const wrongSecretRes = createMockRes();
    await handler(
      { method: "POST", body: { admin_secret: "wrong", html_content: "<h1>Hi</h1>", edit_pin: "1234" } },
      wrongSecretRes
    );
    assert.equal(wrongSecretRes.statusCode, 401);
  });

  it("validates empty HTML, invalid PIN, reserved/invalid slug, and malformed JSON", async () => {
    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => createMockSupabase(),
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });

    const badJsonRes = createMockRes();
    await handler({ method: "POST", body: "{not-json" }, badJsonRes);
    assert.equal(badJsonRes.statusCode, 400);

    const emptyHtmlRes = createMockRes();
    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, html_content: "   ", edit_pin: "1234" } },
      emptyHtmlRes
    );
    assert.equal(emptyHtmlRes.statusCode, 400);

    const badPinRes = createMockRes();
    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, html_content: "<h1>Hi</h1>", edit_pin: "12a4" } },
      badPinRes
    );
    assert.equal(badPinRes.statusCode, 400);

    const reservedApiRes = createMockRes();
    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, slug: "api", html_content: "<h1>Hi</h1>", edit_pin: "1234" } },
      reservedApiRes
    );
    assert.equal(reservedApiRes.statusCode, 400);

    const reservedEditorRes = createMockRes();
    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, slug: "editor", html_content: "<h1>Hi</h1>", edit_pin: "1234" } },
      reservedEditorRes
    );
    assert.equal(reservedEditorRes.statusCode, 400);

    const badCharSlugRes = createMockRes();
    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, slug: "a b", html_content: "<h1>Hi</h1>", edit_pin: "1234" } },
      badCharSlugRes
    );
    assert.equal(badCharSlugRes.statusCode, 400);
  });

  it("rejects HTML payloads exceeding 2 MB with 413", async () => {
    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => createMockSupabase(),
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });
    const res = createMockRes();
    const oversized = "a".repeat(saveHandler.MAX_HTML_BYTES + 1);
    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, html_content: oversized, edit_pin: "1234" } },
      res
    );
    assert.equal(res.statusCode, 413);
  });

  it("creates a new page with custom slug and hashed PIN", async () => {
    const mockDb = createMockSupabase();
    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => mockDb,
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });
    const res = createMockRes();

    await handler(
      {
        method: "POST",
        body: { admin_secret: TEST_ADMIN_SECRET, slug: "Demo-Page", html_content: "<h1>Hello</h1>", edit_pin: "123456" },
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
    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => mockDb,
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });
    const res = createMockRes();

    await handler(
      {
        method: "POST",
        body: { admin_secret: TEST_ADMIN_SECRET, slug: "trangmoi2026", html_content: "<h1>No Hyphen</h1>", edit_pin: "1234" },
      },
      res
    );

    assert.equal(res.statusCode, 201);
    assert.deepEqual(res.body, { slug: "trangmoi2026", updated: false });
    assert.equal(mockDb.store.get("trangmoi2026").html_content, "<h1>No Hyphen</h1>");
  });

  it("allows 1-character slugs and 'index' slug", async () => {
    const mockDb = createMockSupabase();
    const save = saveHandler.createSaveHandler({
      getSupabaseClient: () => mockDb,
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });
    const view = viewHandler.createViewHandler({ getSupabaseClient: () => mockDb });

    const saveOneRes = createMockRes();
    await save(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, slug: "1", html_content: "<h1>One</h1>", edit_pin: "1234" } },
      saveOneRes
    );
    assert.equal(saveOneRes.statusCode, 201);
    assert.equal(saveOneRes.body.slug, "1");

    const viewOneRes = createMockRes();
    await view({ method: "GET", query: { slug: "1" } }, viewOneRes);
    assert.equal(viewOneRes.statusCode, 200);
    assert.equal(viewOneRes.body, "<h1>One</h1>");

    const saveIndexRes = createMockRes();
    await save(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, slug: "index", html_content: "<h1>Index Slug</h1>", edit_pin: "1234" } },
      saveIndexRes
    );
    assert.equal(saveIndexRes.statusCode, 201);
    assert.equal(saveIndexRes.body.slug, "index");

    const viewIndexRes = createMockRes();
    await view({ method: "GET", query: { slug: "index" } }, viewIndexRes);
    assert.equal(viewIndexRes.statusCode, 200);
    assert.equal(viewIndexRes.body, "<h1>Index Slug</h1>");
  });

  it("auto-generates a valid slug when omitted", async () => {
    const mockDb = createMockSupabase();
    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => mockDb,
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });
    const res = createMockRes();

    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, html_content: "<p>Auto</p>", edit_pin: "4321" } },
      res
    );

    assert.equal(res.statusCode, 201);
    assert.match(res.body.slug, /^[a-f0-9]{8}$/);
    assert.equal(mockDb.store.has(res.body.slug), true);
  });

  it("returns 409 when creating with an already-existing slug or on Postgres 23505 race condition", async () => {
    const mockDb = createMockSupabase([
      { slug: "taken", html_content: "<p>Old</p>", edit_pin: saveHandler.hashPin("1234") },
    ]);
    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => mockDb,
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });
    const res = createMockRes();

    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, slug: "taken", html_content: "<p>New</p>", edit_pin: "1234" } },
      res
    );
    assert.equal(res.statusCode, 409);

    const raceDb = createMockSupabase([], { insertErrorCode: "23505" });
    const raceHandler = saveHandler.createSaveHandler({
      getSupabaseClient: () => raceDb,
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });
    const raceRes = createMockRes();
    await raceHandler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, slug: "race-slug", html_content: "<p>New</p>", edit_pin: "1234" } },
      raceRes
    );
    assert.equal(raceRes.statusCode, 409);
  });

  it("updates an existing page only when PIN matches, locks out after 5 wrong PINs (429), and resets on success", async () => {
    let fakeNow = 1_700_000_000_000;
    const mockDb = createMockSupabase([
      { slug: "my-site", html_content: "<h1>V1</h1>", edit_pin: saveHandler.hashPin("7788") },
    ]);
    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => mockDb,
      getAdminSecret: () => TEST_ADMIN_SECRET,
      now: () => fakeNow,
    });

    const missingRes = createMockRes();
    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, mode: "edit", slug: "unknown", html_content: "<h1>V2</h1>", edit_pin: "7788" } },
      missingRes
    );
    assert.equal(missingRes.statusCode, 404);

    // 4 wrong PIN attempts -> 403
    for (let i = 0; i < 4; i++) {
      const wrongRes = createMockRes();
      await handler(
        { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, mode: "edit", slug: "my-site", html_content: "<h1>V2</h1>", edit_pin: "0000" } },
        wrongRes
      );
      assert.equal(wrongRes.statusCode, 403);
    }

    // 5th wrong PIN attempt -> 429 lockout
    const lockRes = createMockRes();
    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, mode: "edit", slug: "my-site", html_content: "<h1>V2</h1>", edit_pin: "0000" } },
      lockRes
    );
    assert.equal(lockRes.statusCode, 429);

    // Even correct PIN is blocked during 15-minute lockout
    const blockedCorrectRes = createMockRes();
    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, mode: "edit", slug: "my-site", html_content: "<h1>V2</h1>", edit_pin: "7788" } },
      blockedCorrectRes
    );
    assert.equal(blockedCorrectRes.statusCode, 429);

    // Advance time past 15 minutes -> correct PIN succeeds and resets failed_attempts
    fakeNow += 16 * 60 * 1000;
    const okRes = createMockRes();
    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, mode: "edit", slug: "my-site", html_content: "<h1>V2</h1>", edit_pin: "7788" } },
      okRes
    );
    assert.equal(okRes.statusCode, 200);
    assert.deepEqual(okRes.body, { slug: "my-site", updated: true });
    assert.equal(mockDb.store.get("my-site").html_content, "<h1>V2</h1>");
    assert.equal(mockDb.store.get("my-site").failed_attempts, 0);
    assert.equal(mockDb.store.get("my-site").locked_until, null);
  });

  it("returns 500 when Supabase reports a database error", async () => {
    const mockDb = createMockSupabase([], { insertError: "DB down" });
    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => mockDb,
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });
    const res = createMockRes();

    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, slug: "ok-slug", html_content: "<p>Hi</p>", edit_pin: "1234" } },
      res
    );

    assert.equal(res.statusCode, 500);
  });

  it("allows admin to create without PIN and edit with admin_override without PIN", async () => {
    const mockDb = createMockSupabase();
    const handler = saveHandler.createSaveHandler({
      getSupabaseClient: () => mockDb,
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });

    const createRes = createMockRes();
    await handler(
      { method: "POST", body: { admin_secret: TEST_ADMIN_SECRET, slug: "no-pin-page", html_content: "<h1>V1</h1>" } },
      createRes
    );
    assert.equal(createRes.statusCode, 201);
    assert.ok(mockDb.store.get("no-pin-page").edit_pin.includes(":"));

    const editRes = createMockRes();
    await handler(
      {
        method: "POST",
        body: {
          admin_secret: TEST_ADMIN_SECRET,
          mode: "edit",
          admin_override: true,
          slug: "no-pin-page",
          html_content: "<h1>V2</h1>",
        },
      },
      editRes
    );
    assert.equal(editRes.statusCode, 200);
    assert.equal(mockDb.store.get("no-pin-page").html_content, "<h1>V2</h1>");
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

  it("returns 200 with HTML content and sandbox isolation headers", async () => {
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
    assert.equal(res.headers["referrer-policy"], "no-referrer");
    assert.equal(
      res.headers["content-security-policy"],
      "sandbox allow-scripts allow-forms allow-popups allow-modals"
    );
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

describe("api/pages admin handler", () => {
  it("rejects unsupported methods with 405 and wrong/missing admin secret with 401/500", async () => {
    const noSecretHandler = pagesHandler.createPagesHandler({
      getSupabaseClient: () => createMockSupabase(),
      getAdminSecret: () => "",
    });
    const noSecretRes = createMockRes();
    await noSecretHandler({ method: "GET", headers: { "x-admin-secret": "11111" } }, noSecretRes);
    assert.equal(noSecretRes.statusCode, 500);

    const handler = pagesHandler.createPagesHandler({
      getSupabaseClient: () => createMockSupabase(),
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });

    const postRes = createMockRes();
    await handler({ method: "POST", headers: { "x-admin-secret": TEST_ADMIN_SECRET } }, postRes);
    assert.equal(postRes.statusCode, 405);

    const unauthRes = createMockRes();
    await handler({ method: "GET", headers: { "x-admin-secret": "wrong" } }, unauthRes);
    assert.equal(unauthRes.statusCode, 401);
  });

  it("lists pages on GET and deletes page on DELETE", async () => {
    const mockDb = createMockSupabase([
      { slug: "page-a", html_content: "<h1>A</h1>", edit_pin: "hash", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
      { slug: "page-b", html_content: "<h1>B</h1>", edit_pin: "hash", created_at: "2026-01-02T00:00:00Z", updated_at: "2026-01-02T00:00:00Z" },
    ]);
    const handler = pagesHandler.createPagesHandler({
      getSupabaseClient: () => mockDb,
      getAdminSecret: () => TEST_ADMIN_SECRET,
    });

    const listRes = createMockRes();
    await handler({ method: "GET", headers: { "x-admin-secret": TEST_ADMIN_SECRET } }, listRes);
    assert.equal(listRes.statusCode, 200);
    assert.equal(listRes.body.pages.length, 2);

    const badDeleteRes = createMockRes();
    await handler({ method: "DELETE", headers: { "x-admin-secret": TEST_ADMIN_SECRET }, query: { slug: "api" } }, badDeleteRes);
    assert.equal(badDeleteRes.statusCode, 400);

    const missingDeleteRes = createMockRes();
    await handler({ method: "DELETE", headers: { "x-admin-secret": TEST_ADMIN_SECRET }, query: { slug: "not-found" } }, missingDeleteRes);
    assert.equal(missingDeleteRes.statusCode, 404);

    const deleteRes = createMockRes();
    await handler({ method: "DELETE", headers: { "x-admin-secret": TEST_ADMIN_SECRET }, query: { slug: "page-a" } }, deleteRes);
    assert.equal(deleteRes.statusCode, 200);
    assert.deepEqual(deleteRes.body, { deleted: true, slug: "page-a" });
    assert.equal(mockDb.store.has("page-a"), false);
  });
});
