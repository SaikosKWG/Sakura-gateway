const https = require('https');
const http  = require('http');

const PORT = process.env.PORT || 3000;

// ── Helpers ──────────────────────────────────────────────────────────────────

function httpsPost(hostname, port, path, body, headers) {
    return new Promise((resolve) => {
        const data = typeof body === 'string' ? body : JSON.stringify(body);
        const opts = {
            hostname, port, path,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data),
                ...headers
            },
            rejectUnauthorized: false,
            timeout: 8000
        };
        let out = '';
        const req = https.request(opts, res => {
            res.on('data', d => out += d);
            res.on('end', () => resolve({ status: res.statusCode, body: out }));
        });
        req.on('error', () => resolve({ status: 0, body: '' }));
        req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: '' }); });
        req.write(data);
        req.end();
    });
}

function httpsGet(hostname, port, path, headers) {
    return new Promise((resolve) => {
        const opts = {
            hostname, port, path,
            method: 'GET',
            headers: { ...headers },
            rejectUnauthorized: false,
            timeout: 8000
        };
        let out = '';
        const req = https.request(opts, res => {
            res.on('data', d => out += d);
            res.on('end', () => resolve({ status: res.statusCode, body: out }));
        });
        req.on('error', () => resolve({ status: 0, body: '' }));
        req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: '' }); });
        req.end();
    });
}

// Encode protobuf field (wire type 2 = length-delimited)
function pbField(tag, str) {
    if (!str) return Buffer.alloc(0);
    const val = Buffer.from(str, 'utf8');
    const tagBuf = Buffer.from([tag]);
    // varint encode length
    let len = val.length;
    const lenBufs = [];
    do {
        lenBufs.push((len & 0x7F) | (len > 0x7F ? 0x80 : 0));
        len >>= 7;
    } while (len > 0);
    return Buffer.concat([tagBuf, Buffer.from(lenBufs), val]);
}

function buildProtobuf(accessToken, entitlement, puuid) {
    return Buffer.concat([
        pbField(0x0A, accessToken),                          // field 1: access_token
        pbField(0x12, entitlement),                          // field 2: entitlement_token
        pbField(0x1A, 'https://auth.riotgames.com'),         // field 3: issuer
        puuid ? pbField(0x22, puuid) : Buffer.alloc(0),     // field 4: subject (puuid)
    ]);
}

function jstr(obj, key) {
    try { return (typeof obj === 'string' ? JSON.parse(obj) : obj)[key] || ''; }
    catch { return ''; }
}

function extractPuuid(jwt) {
    try {
        const parts = jwt.split('.');
        if (parts.length < 2) return '';
        let b64 = parts[1].replace(/-/g,'+').replace(/_/g,'/');
        while (b64.length % 4) b64 += '=';
        const payload = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
        return payload.sub || '';
    } catch { return ''; }
}

// ── Request handler ──────────────────────────────────────────────────────────

async function handle(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

    const url = req.url.split('?')[0];

    // ── Health check ──────────────────────────────────────────────────────────
    if (req.method === 'GET' && (url === '/' || url === '/health')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', service: 'sakura-gateway' }));
        return;
    }

    // ── Gateway endpoint (/gw.php pour compat loader) ─────────────────────────
    if (req.method === 'POST' && (url === '/gw.php' || url === '/gw' || url === '/gateway')) {
        let body = '';
        req.on('data', d => body += d);
        req.on('end', async () => {
            let parsed;
            try { parsed = JSON.parse(body); } catch {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'invalid json' }));
                return;
            }

            const jwt = (parsed.gametoken || '').trim();
            if (!jwt || !jwt.startsWith('eyJ')) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'invalid token' }));
                return;
            }

            const puuid = extractPuuid(jwt);

            // Étape 1 : obtenir l'entitlement token
            let entitlement = '';
            const entR = await httpsPost(
                'entitlements.auth.riotgames.com', 443,
                '/api/token/v1', '{}',
                {
                    'Authorization': `Bearer ${jwt}`,
                    'Content-Type': 'application/json',
                    'User-Agent': 'RiotClient/99.0.0.0.0 rso-auth (Windows;10;;Professional, x64)'
                }
            );
            if (entR.status === 200) {
                try {
                    const ent = JSON.parse(entR.body);
                    entitlement = ent.accessToken || ent.access_token || ent.entitlements_token || '';
                } catch {}
            }

            // Fallback : utiliser le JWT directement
            if (!entitlement) entitlement = jwt;

            // Étape 2 : construire le payload protobuf
            const pb = buildProtobuf(jwt, entitlement, puuid);

            // Encode en base64url
            const encoded = pb.toString('base64')
                .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ data: encoded, source: 'sakura-relay' }));
        });
        return;
    }

    // ── Validate key endpoint (pour key_vault) ────────────────────────────────
    if (req.method === 'POST' && url === '/validate.php') {
        let body = '';
        req.on('data', d => body += d);
        req.on('end', async () => {
            // Délègue à validate.php via le même processus
            // Pour Railway Node.js, on gère tout ici
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ valid: false, reason: 'use local panel' }));
        });
        return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
}

const server = http.createServer(handle);
server.listen(PORT, () => console.log(`Sakura Gateway running on port ${PORT}`));
