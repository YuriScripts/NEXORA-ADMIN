import { jwtVerify, createRemoteJWKSet } from "jose";

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });

async function authenticate(request, env) {
  const token = request.headers.get("Cf-Access-Jwt-Assertion");

  if (!token) throw new Error("Authentication required.");

  const team = env.ACCESS_TEAM_DOMAIN.replace(/\/$/, "");
  const issuer = team.startsWith("https://")
    ? team
    : `https://${team}`;

  const JWKS = createRemoteJWKSet(
    new URL(`${issuer}/cdn-cgi/access/certs`)
  );

  const { payload } = await jwtVerify(token, JWKS, {
    issuer,
    audience: env.ACCESS_AUD
  });

  const email = String(payload.email || "").toLowerCase();
  const allowed = String(env.ADMIN_EMAIL || "").toLowerCase();

  if (!email || !allowed || email !== allowed) {
    throw new Error("Administrator access denied.");
  }

  return email;
}

async function hashKey(key) {
  const bytes = new TextEncoder().encode(key);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return [...new Uint8Array(digest)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function generateKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  const encoded = btoa(
    String.fromCharCode(...bytes)
  ).replace(/\+/g, "-")
   .replace(/\//g, "_")
   .replace(/=/g, "");

  return `NX-${encoded}`;
}

async function readLicenses(env) {
  const result = await env.LICENSE_DB.list({
    prefix: "license:",
    limit: 1000
  });

  const records = await Promise.all(
    result.keys.map(async entry => {
      const value = await env.LICENSE_DB.get(entry.name, "json");

      if (!value) return null;

      return {
        ...value,
        status:
          value.revoked
            ? "revoked"
            : Date.now() >= Date.parse(value.expiresAt)
              ? "expired"
              : "active"
      };
    })
  );

  return records
    .filter(Boolean)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Authenticate administrator before accessing API.
      const email = await authenticate(request, env);

      if (request.method === "GET" && path === "/api/admin/me") {
        return json({
          authenticated: true,
          email
        });
      }

      if (request.method === "GET" && path === "/api/licenses") {
        const licenses = await readLicenses(env);

        return json({ licenses });
      }

      // Generate exactly ONE license per request.
      if (request.method === "POST" && path === "/api/licenses") {
        let body;

        try {
          body = await request.json();
        } catch {
          return json({ error: "Invalid JSON body." }, 400);
        }

        const owner = String(body.owner || "").trim();
        const days = Number(body.days);

        if (!owner || owner.length > 60) {
          return json({ error: "Invalid license owner." }, 400);
        }

        if (!Number.isInteger(days) || days < 1 || days > 3650) {
          return json({ error: "Validity must be 1–3650 days." }, 400);
        }

        const key = generateKey();
        const hash = await hashKey(key);
        const id = crypto.randomUUID();

        const now = new Date();
        const expires = new Date(
          now.getTime() + days * 86400000
        );

        const record = {
          id,
          owner,
          createdAt: now.toISOString(),
          expiresAt: expires.toISOString(),
          revoked: false,
          createdBy: email
        };

        // Store license metadata and a hash-to-ID index.
        await env.LICENSE_DB.put(
          `license:${id}`,
          JSON.stringify(record)
        );

        await env.LICENSE_DB.put(
          `hash:${hash}`,
          id
        );

        // The original key is returned only once.
        return json({
          success: true,
          key,
          license: {
            ...record,
            status: "active"
          }
        }, 201);
      }

      // Revoke a license.
      const revokeMatch = path.match(
        /^\/api\/licenses\/([a-f0-9-]+)\/revoke$/i
      );

      if (request.method === "POST" && revokeMatch) {
        const id = revokeMatch[1];

        const storageKey = `license:${id}`;
        const record = await env.LICENSE_DB.get(storageKey, "json");

        if (!record) {
          return json({ error: "License not found." }, 404);
        }

        if (record.revoked) {
          return json({ error: "License already revoked." }, 409);
        }

        record.revoked = true;
        record.revokedAt = new Date().toISOString();
        record.revokedBy = email;

        await env.LICENSE_DB.put(
          storageKey,
          JSON.stringify(record)
        );

        return json({
          success: true,
          message: "License revoked."
        });
      }

      return json({ error: "API endpoint not found." }, 404);

    } catch (error) {
      console.error("NEXORA API error:", error.message);

      return json({
        error: error.code === "ERR_JWT_EXPIRED"
          ? "Your session expired. Please sign in again."
          : "Unauthorized or server error."
      }, 401);
    }
  }
};
