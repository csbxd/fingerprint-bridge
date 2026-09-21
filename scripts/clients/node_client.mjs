import https from 'node:https';
import http2 from 'node:http2';
import fs from 'node:fs';
import assert from 'node:assert/strict';

const [caPath, hosts, protocol, aPort, bPort] = process.argv.slice(2);
const ca = fs.readFileSync(caPath);
const lookup = (_host, options, done) => options.all
  ? done(null, [{ address: '127.0.0.1', family: 4 }]) : done(null, '127.0.0.1', 4);
for (const [host, port] of [['a.test', aPort], ['a.test', aPort], ['b.test', bPort]]) {
  const base = `https://${host}:${port}`;
  const headers = { 'user-agent': 'fp-matrix/node', cookie: 'sid=from_B; flag=yes',
    origin: base, referer: `${base}/home`, 'x-order-z': 'z', 'x-order-a': 'a' };
  const verify = (h, body) => {
    assert.equal(body, 'FP_OK');
    assert.ok(h['set-cookie'][0].includes(`Domain=${host}`));
    assert.equal(h.location, `${base}/next`);
  };
  if (protocol === 'h2') {
    const session = http2.connect(base, { ca, lookup });
    session.setTimeout(15000, () => session.destroy(new Error('h2 timeout')));
    await new Promise((resolve, reject) => {
      session.once('connect', resolve); session.once('error', reject);
    });
    try {
      for (const n of [1, 2]) await new Promise((resolve, reject) => {
        const request = session.request({ ':method': 'GET', ':path': `/fingerprint/${n}?encoded=%2F`, ...headers });
        let responseHeaders, body = '';
        request.setEncoding('utf8');
        request.on('response', h => { responseHeaders = h; });
        request.on('data', b => { body += b; });
        request.on('error', reject);
        request.on('end', () => { try { assert.equal(responseHeaders[':status'], 200); verify(responseHeaders, body); resolve(); } catch (e) { reject(e); } });
        request.end();
      });
    } finally { session.close(); }
  } else {
    const agent = new https.Agent({ keepAlive: true, maxSockets: 1, maxCachedSessions: 0, ca, lookup, ALPNProtocols: ['http/1.1'] });
    try {
      for (const n of [1, 2]) await new Promise((resolve, reject) => {
        const request = https.get(`${base}/fingerprint/${n}?encoded=%2F`, { agent, headers }, response => {
          let body = ''; response.setEncoding('utf8');
          response.on('data', b => { body += b; });
          response.on('error', reject);
          response.on('end', () => { try { assert.equal(response.statusCode, 200); assert.equal(response.httpVersion, '1.1'); verify(response.headers, body); resolve(); } catch (e) { reject(e); } });
        });
        request.setTimeout(15000, () => request.destroy(new Error('https timeout')));
        request.on('error', reject);
      });
    } finally { agent.destroy(); }
  }
}
console.log(JSON.stringify({ node: process.version, openssl: process.versions.openssl }));
