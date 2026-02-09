# 04 — Nginx & Let's Encrypt SSL

Set up Nginx as a web server on ports 80/443 with a free Let's Encrypt SSL certificate via Certbot.

## Prerequisites

- Ports 80 and 443 open in UFW (done in [02-firewall-fail2ban.md](02-firewall-fail2ban.md))
- A domain name (e.g. `example.com`) with an A record pointing to your VPS IP

## 1. Install Nginx

```bash
sudo apt install nginx -y
```

### Verify Nginx is Running

```bash
sudo systemctl status nginx
curl -I http://localhost
```

You should see the default Nginx welcome page at `http://YOUR_SERVER_IP`.

---

## 2. Create a Welcome Page

Replace the default page with your own:

```bash
sudo mkdir -p /var/www/example.com/html
sudo chown -R $USER:$USER /var/www/example.com/html
```

Create the page:

```bash
cat << 'HTMLEOF' | sudo tee /var/www/example.com/html/index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #0f172a;
            color: #e2e8f0;
        }
        .container {
            text-align: center;
            padding: 2rem;
        }
        h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
        p { color: #94a3b8; font-size: 1.1rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome</h1>
        <p>This server is secured and ready.</p>
    </div>
</body>
</html>
HTMLEOF
```

---

## 3. Configure Nginx Server Block

Create a server block for your domain:

```bash
sudo nano /etc/nginx/sites-available/example.com
```

Add:

```nginx
server {
    listen 80;
    listen [::]:80;

    server_name example.com www.example.com;
    root /var/www/example.com/html;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}
```

Enable the site and test:

```bash
sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default    # remove default site
sudo nginx -t                                # test config
sudo systemctl reload nginx
```

Verify: visit `http://example.com` — you should see your welcome page.

---

## 4. Install Certbot & Obtain SSL Certificate

Install Certbot with the Nginx plugin:

```bash
sudo apt install certbot python3-certbot-nginx -y
```

Obtain and install the certificate:

```bash
sudo certbot --nginx -d example.com -d www.example.com
```

Certbot will:
1. Ask for your email (for renewal notices)
2. Ask you to agree to the Terms of Service
3. Automatically configure Nginx for HTTPS
4. Set up HTTP-to-HTTPS redirect

### Verify HTTPS

```bash
curl -I https://example.com
```

---

## 5. Auto-Renewal

Certbot installs a systemd timer for automatic renewal. Verify it's active:

```bash
sudo systemctl status certbot.timer
```

Test renewal (dry run):

```bash
sudo certbot renew --dry-run
```

Certificates renew automatically when they're within 30 days of expiry.

---

## 6. Harden Nginx SSL (optional)

After Certbot configures SSL, you can further harden it. Edit your site config:

```bash
sudo nano /etc/nginx/sites-available/example.com
```

Add inside the `server` block that listens on 443:

```nginx
    # Strong SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    # HSTS (1 year)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

Reload:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Test your SSL grade at [SSL Labs](https://www.ssllabs.com/ssltest/).

---

## 7. Using Nginx as a Reverse Proxy (optional)

If you're running an app (e.g. on port 3000), add a `location` block:

```nginx
location /app/ {
    proxy_pass http://127.0.0.1:3000/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## What's Next

See the [Quick Reference Checklist](quick-checklist.md) for a condensed, copy-paste version of all steps.
