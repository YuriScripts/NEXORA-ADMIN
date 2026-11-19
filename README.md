# NEXORA ADMIN

Private license management dashboard.

## Features

- Cloudflare Access administrator authentication
- License key generation
- Secure SHA-256 license hash storage
- License expiration
- License history
- License revocation
- Dashboard statistics
- Responsive interface

## Requirements

- Cloudflare account
- GitHub repository
- Node.js and npm
- Cloudflare Pages
- Cloudflare Workers
- Cloudflare KV
- Cloudflare Zero Trust Access

## Installation

### 1. Install dependencies

Open the worker directory:

```bash
cd worker
npm install
```

### 2. Create KV database

```bash
npx wrangler kv namespace create LICENSE_DB
```

Copy the namespace ID into wrangler.toml.

### 3. Configure Cloudflare

Set these values in wrangler.toml:

- ACCESS_TEAM_DOMAIN
- ACCESS_AUD
- ADMIN_EMAIL

### 4. Deploy the Worker

```bash
npx wrangler deploy
```

### 5. Deploy the website

Upload the repository to GitHub.

Connect the repository to Cloudflare Pages.

Set the Pages build output directory to:

```text
/
```

No build command is required.

### 6. Configure Worker routing

Attach your Worker to your website domain using:

```text
yourdomain.com/api/*
```

### 7. Configure Cloudflare Access

Create a self-hosted Access application covering:

```text
nexora.yourdomain.com/*
```

Create an Allow policy with:

- Include: Emails
- Value: YOUR-ADMIN-EMAIL@example.com

Copy the application's AUD tag into wrangler.toml.

Only your authorized email should be allowed.

## Security

- Administrator identity verified using Cloudflare Access JWT.
- License keys generated using cryptographically secure randomness.
- Only SHA-256 hashes are stored.
- Original license keys are displayed once.
- Revoked licenses cannot be reactivated through this dashboard.

# NEXORA ADMIN
