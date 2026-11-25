const SESSION_TTL = 8 * 60 * 60;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function corsHeaders(origin, env) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Vary": "Origin"
  };

  if (origin && origin === env.ADMIN_ORIGIN) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
    headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS";
  }

  return headers;
}

function json(data, status = 200, origin = null, env = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders(origin, env)
  });
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function decodeBase64url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

async function importSigningKey(secret) {
  return crypto.subtle.importKey(
    "raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
  );
}

async function sign(data, secret) {
  const key = await importSigningKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return base64url(new Uint8Array(signature));
}

async function createToken(sid, secret) {
  const payload = base64url(encoder.encode(JSON.stringify({
    sid, exp: Math.floor(Date.now() / 1000) + SESSION_TTL
  })));
  return payload + "." + await sign(payload, secret);
}

async function verifyToken(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 2) return null;
    const [payload, signature] = parts;
    const key = await importSigningKey(secret);
    const valid = await crypto.subtle.verify(
      "HMAC", key, decodeBase64url(signature), encoder.encode(payload)
    );
    if (!valid) return null;
    const data = JSON.parse(decoder.decode(decodeBase64url(payload)));
    if (!data.sid || !Number.isFinite(data.exp)) return null;
    if (data.exp <= Math.floor(Date.now() / 1000)) return null;
    return data;
  } catch { return null; }
}

async function hashKey(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2, "0")).join("");
}

function generateKey() {
  return "NX-" + base64url(crypto.getRandomValues(new Uint8Array(32)));
}

// License keys are encrypted at rest for authenticated admin recovery. The
// existing SESSION_SECRET is used to derive the AES-GCM key; keep it backed up.
async function encryptionKey(secret) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode("NEXORA-LICENSE-KEYS:" + secret));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function encryptLicenseKey(value, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await encryptionKey(secret);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return { keyEncrypted: base64url(new Uint8Array(encrypted)), keyIv: base64url(iv) };
}
async function decryptLicenseKey(record, secret) {
  if (!record || !record.keyEncrypted || !record.keyIv) return null;
  try {
    const key = await encryptionKey(secret);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: decodeBase64url(record.keyIv) }, key, decodeBase64url(record.keyEncrypted));
    return decoder.decode(plain);
  } catch { return null; }
}
function cleanDeviceText(value, max = 120) {
  if (typeof value !== "string") return null;
  const clean = value.replace(/[\u0000-\u001f\u007f]/g, " ").trim().replace(/\s+/g, " ");
  return clean ? clean.slice(0, max) : null;
}

function constantTimeEqual(a, b) {
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  let difference = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    difference |= (x[i] || 0) ^ (y[i] || 0);
  }
  return difference === 0;
}

async function authenticate(request, env) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Bearer ")) return false;
  const data = await verifyToken(header.slice(7), env.SESSION_SECRET);
  if (!data) return false;
  return (await env.LICENSE_DB.get("session:" + data.sid)) === "admin";
}

async function readLicenses(env) {
  const result = await env.LICENSE_DB.list({ prefix: "license:", limit: 1000 });
  const records = await Promise.all(result.keys.map(async entry => {
    const value = await env.LICENSE_DB.get(entry.name, "json");
    if (!value) return null;
    const expired = !value.lifetime && (!value.expiresAt || Date.now() >= Date.parse(value.expiresAt));
    const status = value.revoked ? "revoked" : expired ? "expired" : "active";
    const licenseKey = await decryptLicenseKey(value, env.SESSION_SECRET);
    return { ...value, keyEncrypted: undefined, keyIv: undefined, licenseKey, status, deviceBound: Boolean(value.deviceId) };
  }));
  return records.filter(Boolean).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

function validDeviceId(value) {
  return typeof value === "string" && /^[a-f0-9-]{36}$/i.test(value);
}

function validLicense(record) {
  return Boolean(record && !record.revoked &&
    (record.lifetime === true || (Number.isFinite(Date.parse(record.expiresAt)) &&
    Date.now() < Date.parse(record.expiresAt))));
}

async function deleteHashMappings(env, id) {
  let cursor;
  do {
    const options = { prefix: "hash:", limit: 1000 };
    if (cursor) options.cursor = cursor;
    const page = await env.LICENSE_DB.list(options);

    for (const entry of page.keys) {
      const mappedId = await env.LICENSE_DB.get(entry.name);
      if (mappedId === id) await env.LICENSE_DB.delete(entry.name);
    }

    cursor = page.cursor;
    if (page.list_complete) break;
  } while (cursor);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const origin = request.headers.get("Origin");

    try {
      if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET || !env.LICENSE_DB || !env.ADMIN_ORIGIN) {
        return json({ error: "Server configuration incomplete." }, 500, origin, env);
      }

      if (env.SESSION_SECRET.length < 32) {
        return json({ error: "Session secret must be at least 32 characters." }, 500, origin, env);
      }

      if (origin && origin !== env.ADMIN_ORIGIN) {
        return json({ error: "Origin not allowed." }, 403, origin, env);
      }

      if (request.method === "OPTIONS") {
        if (!origin || origin !== env.ADMIN_ORIGIN) return new Response(null, { status: 403 });
        return new Response(null, {
          status: 204,
          headers: { ...corsHeaders(origin, env), "Access-Control-Max-Age": "600" }
        });
      }

      /* ADMIN LOGIN */
      if (request.method === "POST" && path === "/api/login") {
        const body = await request.json();
        const password = String(body.password || "");
        if (!constantTimeEqual(password, env.ADMIN_PASSWORD)) {
          return json({ error: "Invalid password." }, 401, origin, env);
        }

        const sid = crypto.randomUUID();
        await env.LICENSE_DB.put("session:" + sid, "admin", { expirationTtl: SESSION_TTL });
        const token = await createToken(sid, env.SESSION_SECRET);
        return json({ success: true, token, expiresIn: SESSION_TTL }, 200, origin, env);
      }

      /* SESSION VERIFICATION */
      if (request.method === "GET" && path === "/api/admin/me") {
        if (!await authenticate(request, env)) {
          return json({ error: "Unauthorized." }, 401, origin, env);
        }
        return json({ authenticated: true }, 200, origin, env);
      }

      /* LOGOUT */
      if (request.method === "POST" && path === "/api/logout") {
        const header = request.headers.get("Authorization") || "";
        if (header.startsWith("Bearer ")) {
          const data = await verifyToken(header.slice(7), env.SESSION_SECRET);
          if (data) await env.LICENSE_DB.delete("session:" + data.sid);
        }
        return json({ success: true }, 200, origin, env);
      }

      /* PUBLIC LICENSE VALIDATION */
      if (request.method === "POST" && path === "/api/validate") {
        const body = await request.json();
        const key = String(body.key || "").trim();
        const deviceId = body.deviceId;

        if (!key || key.length > 100 || !validDeviceId(deviceId)) {
          return json({ valid: false, error: "Invalid license credentials." }, 400, origin, env);
        }

        const hash = await hashKey(key);
        const id = await env.LICENSE_DB.get("hash:" + hash);
        if (!id) return json({ valid: false, error: "Invalid license key." }, 403, origin, env);

        const storageKey = "license:" + id;
        const license = await env.LICENSE_DB.get(storageKey, "json");
        if (!validLicense(license)) {
          return json({ valid: false, error: "License expired or revoked." }, 403, origin, env);
        }

        // Optional device telemetry from the licensed desktop app. Only update
        // after the key is valid and the device binding is accepted.
        const reportedCpu = cleanDeviceText(body.cpu, 120);
        const reportedWindows = cleanDeviceText(body.windows || body.os, 120);

        if (!license.deviceId) {
          license.deviceId = deviceId;
          license.deviceBoundAt = new Date().toISOString();
          await env.LICENSE_DB.put(storageKey, JSON.stringify(license));
        } else if (license.deviceId !== deviceId) {
          return json({
            valid: false,
            error: "This license is already activated on another device."
          }, 403, origin, env);
        }

        if (reportedCpu) license.cpu = reportedCpu;
        if (reportedWindows) license.windows = reportedWindows;
        license.lastSeen = new Date().toISOString();
        await env.LICENSE_DB.put(storageKey, JSON.stringify(license));

        return json({
          valid: true,
          owner: license.owner,
          expiresAt: license.expiresAt,
          deviceBound: true
        }, 200, origin, env);
      }

      /* ADMIN AUTH REQUIRED */
      if (!await authenticate(request, env)) {
        return json({ error: "Unauthorized." }, 401, origin, env);
      }

      /* DELETE REVOKED LICENSE */
      if (request.method === "DELETE" && /^\/api\/licenses\/[a-f0-9-]+$/i.test(path)) {
        const id = path.split("/").pop();
        const storageKey = "license:" + id;
        const record = await env.LICENSE_DB.get(storageKey, "json");

        if (!record) return json({ error: "License not found." }, 404, origin, env);

        const expired = !record.lifetime && (!record.expiresAt || Date.now() >= Date.parse(record.expiresAt));
        if (!record.revoked && !expired) {
          return json({ error: "Only revoked or expired licenses can be deleted." }, 409, origin, env);
        }

        await deleteHashMappings(env, id);
        await env.LICENSE_DB.delete(storageKey);

        return json({
          success: true,
          message: "License permanently deleted."
        }, 200, origin, env);
      }

      /* LIST LICENSES */
      if (request.method === "GET" && path === "/api/licenses") {
        return json({ licenses: await readLicenses(env) }, 200, origin, env);
      }

      /* GENERATE LICENSE */
      if (request.method === "POST" && path === "/api/licenses") {
        const body = await request.json();
        const owner = String(body.owner || "").trim();
        const lifetime = body.lifetime === true;
        const days = Number(body.days);

        if (!owner || owner.length > 60) {
          return json({ error: "Invalid license owner." }, 400, origin, env);
        }

        if (!lifetime && (!Number.isInteger(days) || days < 1 || days > 3650)) {
          return json({ error: "Validity must be 1–3650 days, or choose lifetime." }, 400, origin, env);
        }

        const key = generateKey();
        const hash = await hashKey(key);
        const encryptedKey = await encryptLicenseKey(key, env.SESSION_SECRET);
        const id = crypto.randomUUID();
        const now = new Date();
        const expires = lifetime ? null : new Date(now.getTime() + days * 86400000);

        const record = {
          id, owner, lifetime,
          createdAt: now.toISOString(),
          expiresAt: expires ? expires.toISOString() : null,
          revoked: false,
          deviceId: null,
          deviceBoundAt: null,
          cpu: null,
          windows: null,
          lastSeen: null,
          ...encryptedKey
        };

        await env.LICENSE_DB.put("license:" + id, JSON.stringify(record));
        await env.LICENSE_DB.put("hash:" + hash, id);

        return json({
          success: true,
          key,
          license: { ...record, status: "active", deviceBound: false }
        }, 201, origin, env);
      }

      /* REVOKE AND UNBIND */
      const match = path.match(/^\/api\/licenses\/([a-f0-9-]+)\/(revoke|unbind)$/i);

      if (match && request.method === "POST") {
        const id = match[1];
        const action = match[2];
        const storageKey = "license:" + id;
        const record = await env.LICENSE_DB.get(storageKey, "json");

        if (!record) return json({ error: "License not found." }, 404, origin, env);

        if (action === "revoke") {
          if (record.revoked) {
            return json({ error: "License already revoked." }, 409, origin, env);
          }
          record.revoked = true;
          record.revokedAt = new Date().toISOString();
        } else if (action === "unbind") {
          if (record.revoked) {
            return json({ error: "Cannot unbind a revoked license." }, 409, origin, env);
          }
          record.deviceId = null;
          record.deviceBoundAt = null;
          record.deviceUnboundAt = new Date().toISOString();
        }

        await env.LICENSE_DB.put(storageKey, JSON.stringify(record));
        return json({ success: true, action }, 200, origin, env);
      }

      return json({ error: "Endpoint not found." }, 404, origin, env);

    } catch (error) {
      console.error("NEXORA API error:", error.message);
      return json({ error: "Internal server error." }, 500, origin, env);
    }
  }
};
