/**
 * STOPGAP: serve allowlisted JSON under /live/* from R2 binding DASH_BUCKET (hunter-public).
 * GET/HEAD only. Edge-caches via caches.default keyed without query string.
 * Replace with custom domain + Cache Rules when a domain is attached.
 *
 * The allowlist matches hunter.public_feed.allowed_public_object_key for live/
 * objects (npm, pypi, github-actions, openvsx, rubygems, crates). Feed keys are not served here.
 * A slash in a release name is a ~ in the path, never %2F. @ in a version is %40.
 * ! ' ( ) * are percent-encoded the same way as urllib.parse.quote.
 */

// Full object key (live/<rel>). Same shape as allowed_public_object_key, without feed.json.
const LIVE_KEY_RE =
  /^live\/(?:live\.json|benchmark\.json|history\/\d{4}-\d{2}-\d{2}\.json|confirmed\/\d{4}-\d{2}-\d{2}\.json|r\/(?:npm|pypi|github-actions|openvsx|rubygems|crates)\/[^/]+\/[^/]+\.json)$/;

const DEFAULT_CC = "public, max-age=2";

function notFound() {
  return new Response("Not found", {
    status: 404,
    headers: { "Cache-Control": "no-store", "Content-Type": "text/plain; charset=utf-8" },
  });
}

function methodNotAllowed() {
  return new Response("Method Not Allowed", {
    status: 405,
    headers: {
      Allow: "GET, HEAD",
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=utf-8",
    },
  });
}

/** Reject path traversal / encoding tricks using the raw URL path (pre-decode). */
function rawPathUnsafe(requestUrl) {
  // request.url path before '?' — keep percent-encoding as sent
  const abs = requestUrl.split("?")[0];
  let pathStart = abs.indexOf("/", abs.indexOf("//") + 2);
  if (pathStart < 0) return true;
  const rawPath = abs.slice(pathStart);
  if (rawPath.includes("\\")) return true;
  if (/%2e/i.test(rawPath) || /%2f/i.test(rawPath) || /%5c/i.test(rawPath)) return true;
  if (rawPath.includes("..")) return true;
  return false;
}

function pathsAgree(rel, caught) {
  if (rel === caught) return true;
  try {
    return decodeURIComponent(rel) === decodeURIComponent(caught);
  } catch (e) {
    return false;
  }
}

// urllib.parse.quote encodes !'()* . encodeURIComponent does not. "~" stays.
function quoteSegment(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, function (ch) {
    return "%" + ch.charCodeAt(0).toString(16).toUpperCase();
  });
}

// Pathname may still contain %XX, or the platform may have decoded it.
// Re-quote either form so the R2 key matches release_object_key.
function canonicalSegment(segment) {
  let text = segment;
  if (segment.includes("%")) {
    try {
      text = decodeURIComponent(segment);
    } catch (e) {
      text = segment;
    }
  }
  return quoteSegment(text);
}

function canonicalRel(rel) {
  return rel.split("/").map(canonicalSegment).join("/");
}

function resolveKey(url, params) {
  if (rawPathUnsafe(url.href)) return null;

  let caught = params && params.path;
  if (Array.isArray(caught)) caught = caught.join("/");
  if (typeof caught !== "string" || caught.length === 0) return null;
  if (caught.includes("..") || caught.includes("\\") || caught.includes("\0")) return null;

  const pathname = url.pathname || "";
  if (!pathname.startsWith("/live/")) return null;
  const rel = pathname.slice("/live/".length);
  if (!rel || rel.includes("..") || rel.includes("\\") || rel.includes("\0")) return null;
  if (/%2e/i.test(rel) || /%2f/i.test(rel) || /%5c/i.test(rel)) return null;
  if (!pathsAgree(rel, caught)) return null;

  const key = `live/${canonicalRel(rel)}`;
  if (!LIVE_KEY_RE.test(key)) return null;
  return key;
}

function parseMaxAge(cc) {
  const m = /(?:^|[,;\s])max-age=(\d+)/i.exec(cc || "");
  if (!m) return 2;
  return Math.max(0, Math.min(86400, parseInt(m[1], 10)));
}

export async function onRequest(context) {
  const { request, env, params, waitUntil } = context;
  const method = request.method;

  if (method !== "GET" && method !== "HEAD") return methodNotAllowed();

  const url = new URL(request.url);
  const key = resolveKey(url, params);
  if (!key) return notFound();

  if (!env.DASH_BUCKET) {
    return new Response("Misconfigured", {
      status: 500,
      headers: { "Cache-Control": "no-store", "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  // Cache key: same origin+pathname, NO query string
  const cacheKey = new Request(`${url.origin}${url.pathname}`, { method: "GET" });
  const cache = caches.default;

  let res = await cache.match(cacheKey);
  if (!res) {
    const obj = await env.DASH_BUCKET.get(key);
    if (!obj) return notFound();

    const cc =
      (obj.httpMetadata && obj.httpMetadata.cacheControl) ||
      obj.cacheControl ||
      DEFAULT_CC;
    const contentType =
      (obj.httpMetadata && obj.httpMetadata.contentType) ||
      "application/json";
    const headers = new Headers({
      "Content-Type": contentType,
      "Cache-Control": cc,
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    });
    if (obj.httpEtag) headers.set("ETag", obj.httpEtag);
    if (obj.uploaded) headers.set("Last-Modified", obj.uploaded.toUTCString());

    res = new Response(obj.body, { status: 200, headers });

    // Edge-cache for at most max-age seconds (Cache API honors Cache-Control)
    const maxAge = parseMaxAge(cc);
    if (maxAge > 0) {
      const toCache = res.clone();
      // Ensure cached response has an explicit TTL via Cache-Control already set
      waitUntil(cache.put(cacheKey, toCache));
    }
  }

  if (method === "HEAD") {
    return new Response(null, { status: res.status, headers: res.headers });
  }
  return res;
}
