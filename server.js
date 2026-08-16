const https = require('https');
const http  = require('http');

const PORT = process.env.PORT || 3000;

function httpsPost(hostname, port, path, body, headers) {
    return new Promise((resolve) => {
        const data = typeof body === 'string' ? body : JSON.stringify(body);
        const opts = {
            hostname, port, path, method: 'POST',
            headers: { 'Content-Type':'application/json', 'Content-Length': Buffer.byteLength(data), ...headers },
            rejectUnauthorized: false, timeout: 8000
        };
        let out = '';
        const req = https.request(opts, res => { res.on('data', d => out+=d); res.on('end', () => resolve({status:res.statusCode,body:out})); });
        req.on('error', () => resolve({status:0,body:''}));
        req.on('timeout', () => { req.destroy(); resolve({status:0,body:''}); });
        req.write(data); req.end();
    });
}

function pbField(tag, str) {
    if (!str) return Buffer.alloc(0);
    const val = Buffer.from(str, 'utf8');
    let len = val.length;
    const lenBufs = [];
    do { lenBufs.push((len & 0x7F) | (len > 0x7F ? 0x80 : 0)); len >>= 7; } while (len > 0);
    return Buffer.concat([Buffer.from([tag]), Buffer.from(lenBufs), val]);
}

function buildProtobuf(accessToken, entitlement, puuid) {
    return Buffer.concat([
        pbField(0x0A, accessToken),
        pbField(0x12, entitlement),
        pbField(0x1A, 'https://auth.riotgames.com'),
        puuid ? pbField(0x22, puuid) : Buffer.alloc(0),
    ]);
}

function extractPuuid(jwt) {
    try {
        const parts = jwt.split('.');
        if (parts.length < 2) return '';
        let b64 = parts[1].replace(/-/g,'+').replace(/_/g,'/');
        while (b64.length % 4) b64 += '=';
        return JSON.parse(Buffer.from(b64,'base64').toString('utf8')).sub || '';
    } catch { return ''; }
}

async function handle(req, res) {
    res.setHeader('Access-Control-Allow-Origin','*');
    if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }
    const url = req.url.split('?')[0];

    if (req.method === 'GET' && (url==='/'||url==='/health')) {
        res.writeHead(200,{'Content-Type':'application/json'});
        res.end(JSON.stringify({status:'ok',service:'sakura-gateway'}));
        return;
    }

    if (req.method === 'POST' && (url==='/gw.php'||url==='/gw'||url==='/gateway')) {
        let body = '';
        req.on('data', d => body+=d);
        req.on('end', async () => {
            let parsed;
            try { parsed = JSON.parse(body); } catch { res.writeHead(400); res.end('{}'); return; }
            const jwt = (parsed.gametoken||'').trim();
            if (!jwt||!jwt.startsWith('eyJ')) { res.writeHead(400); res.end('{}'); return; }
            const puuid = extractPuuid(jwt);

            let entitlement = '';
            const entR = await httpsPost('entitlements.auth.riotgames.com', 443, '/api/token/v1', '{}', {
                'Authorization': `Bearer ${jwt}`,
                'User-Agent': 'RiotClient/99.0.0.0.0 rso-auth (Windows;10;;Professional, x64)',
                'X-Riot-ClientPlatform': 'ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQxLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iDQp9',
                'X-Riot-ClientVersion': 'release-09.09-shipping-10-2444158'
            });
            console.log(`[GW] entitlement status=${entR.status} body=${entR.body.substring(0,120)}`);
            if (entR.status===200) {
                try {
                    const e = JSON.parse(entR.body);
                    entitlement = e.accessToken||e.access_token||e.entitlements_token||e.token||'';
                } catch {}
            }
            if (!entitlement) entitlement = jwt;
            console.log(`[GW] entitlement=${entitlement?'GOT':'FALLBACK'} puuid=${puuid}`);

            const pb = buildProtobuf(jwt, entitlement, puuid);
            const encoded = pb.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
            console.log(`[GW] payload size=${pb.length} encoded_len=${encoded.length}`);
            res.writeHead(200,{'Content-Type':'application/json'});
            res.end(JSON.stringify({data:encoded,source:'sakura-relay'}));
        });
        return;
    }

    res.writeHead(404); res.end('{}');
}

const server = http.createServer(handle);
server.listen(PORT, () => console.log(`Sakura Gateway running on port ${PORT}`));
