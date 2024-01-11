//
// ============== JuNeDNS Backend 2.1.1 ===============
//
// Copyright (c) 2024 Eduardo Ruiz <eruiz@dataclick.es>
// https://github.com/EduardoRuizM/junedns-backend
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE

const fs = require('fs');
const path = require('path');
const util = require('util');
const mysql = require('mysql');
const crypto = require('crypto');
const texts = require('./texts');
const backserver = require('./backserver');

const fcfg = process.cwd() + path.sep + 'junedns.conf';
const flog = process.cwd() + path.sep + 'junedns-backend.log';

// Read and assign configuration
let log = 0, cfg = {};
try {

  fs.readFileSync(fcfg).toString().replace(/\r/g, '').split('\n').map(c => c).forEach((l) => {
    l = l.split('=');
    if(l.length === 2)
      cfg[l[0].trim()] = l[1].trim();
  });

  log = (typeof cfg.backend_log === 'undefined') ? (cfg.log || 0) : cfg.backend_log;

  if(!cfg.backend_url || !cfg.mysql_name || !cfg.mysql_user || !cfg.mysql_pass)
    throw new Error('No URL or database config');

} catch(err) {

  addLog(err, 1);
  process.exit(1);
}

cfg.protocol_ipv6 = !(cfg.protocol_ipv6 === 'false');

if(cfg.backend_api === 'true' && !cfg.backend_apikey) {

  cfg.backend_apikey = crypto.randomBytes(60).toString('base64').replaceAll('/', '0');
  fs.appendFileSync(fcfg, `backend_apikey=${cfg.backend_apikey}\n`);
}

// Database
const db = mysql.createConnection({host: cfg.mysql_host || '127.0.0.1', user: cfg.mysql_user, password: cfg.mysql_pass, database: cfg.mysql_name, port: cfg.mysql_port || 3306});
const query = util.promisify(db.query).bind(db);

// Create admin user
for(let i = 1; i < process.argv.length - 1; i++) {

  if(process.argv[i] === 'createuser' && process.argv[i + 1] && process.argv[i + 2])
    query('INSERT INTO users SET code=?, passwd=?, is_admin=1', [process.argv[i + 1], crypto.scryptSync(process.argv[i + 2], cfg.backend_token.substring(0, 32), 32).toString('hex')]);
}

// Functions
function addLog(txt, type, ip, action) {
  action = action || 'ERR';
  if(type === 1) {

    txt = (typeof txt === 'object') ? ((log == 3) ? txt.stack : txt.message) : txt;
    console.error('JuNeDNS Backend', action, txt);
  }

  if(type > log)
    return;

  const d = (new Date()).toISOString().substring(0, 19).replace('T', ' ');
  try {

    if(fs.existsSync(flog) && fs.statSync(flog).size > 50 * 1024 * 1024)
      fs.writeFileSync(flog, '');

    ip = ip || '';
    txt = `${d} [${action}] IP: <${ip}> ${txt}\n`;
    if(log == 3) //Debug
      console.log(txt);
    else
      fs.appendFileSync(flog, txt);

  } catch(e) {

    console.error('Unable to save log file', e.message);
  }
}

// Token
if(!cfg.backend_token) {

  cfg.backend_token = crypto.generateKeyPairSync('rsa', {modulusLength: 1024}).privateKey.export({type: 'pkcs1', format: 'der'}).toString('base64');
  fs.appendFileSync(fcfg, `backend_token=${cfg.backend_token}\n`)
}

const types =	{SOA: {primary: 'str', admin: 'str', serial: 'int32', refresh: 'int32', retry: 'int32', expiration: 'int32', minimum: 'int32'},
		 A: {address: 'ipv4'},
		 AAAA: {address: 'ipv6'},
		 MX: {exchange: 'str', priority: 'int16'},
		 TXT: {text: 'txt'},
		 SRV: {priority: 'int16', weight: 'int16', port: 'int16', target: 'str'},
		 NS: {ns: 'str'},
		 CNAME: {domain: 'str'},
		 PTR: {domain: 'str'},
		 SPF: {text: 'txt'},
		 CAA: {flags: {0: 0, 1: 1}, tag: {issue: 'issue', issuewild: 'issuewild', iodef: 'iodef'}, value: 'str'},
		 NAPTR: {order: 'int16', preference: 'int16', flags: {S: 'SRV', A: 'A/AAAA/A6', U: 'URI', P: 'Protocol Specific'}, service: 'str', regexp: 'str', replacement: 'str'},
		 TLSA: {usage: {0: '0-Certificate Authority Constraint', 1: '1-Service Certificate Constraint', 2: '2-Trust Anchor Assertion', 3: '3-Domain Issued Certificate'}, selector: {0: '0-Full certificate', 1: '1-Subject Public Key'}, matchingtype: {0: '0-No hash', 1: '1-SHA256', 2: '2-SHA512'}}
		};

// When session check user and language
async function middleware(req, res, next) {
  if(req.getparams.has('lang'))
    app.session.lang = req.getparams.get('lang');
  else if(!app.session.lang)
    app.session.lang = 'en-US';

  app.messages = {missing: texts('missing', app.session.lang), login: texts('st401', app.session.lang)};

  if(!app.session.uid)
    return;

  const result = await query('SELECT * FROM users WHERE id=? LIMIT 1', app.session.uid);
  if(result.length) {

    app.session.user = result[0];
    delete app.session.user.passwd;
  }
}

// SQL Queries
async function dbQuery(req, res, q, v) {
  try {

    req.status = 200;
    return await query(q, v);

  } catch(err) {

    req.status = 400;
    if(err.code === 'ER_DUP_ENTRY')
      err = txt('alreadyexists');
    else if(err.sqlMessage)
      err = err.sqlMessage;

    addLog(err, 1, req.ip);
    req.content.message = err;

  } finally {

    if(req.status >= 400 && !req.content.message)
      req.content.message = txt(`st${req.status}`);
  }
}

async function lastID() {
  const result = await query('SELECT LAST_INSERT_ID() AS id');
  return (result.length) ? result[0].id : 0;
}

// Admin permission for general or (optional) domain with readonly for change/delete
async function checkUser(req, res) {
  if(!app.checkLogin())
    return false;

  // For update token
  const result = await getElm(req, res, 'SELECT * FROM users WHERE id=? LIMIT 1', app.session.uid, true);
  if(result) {

      app.session.user = result;
      delete app.session.user.passwd;
      res.sendHeaders['X-Access-User'] = Buffer.from(JSON.stringify(app.session.user)).toString('base64');
      return true;

  } else {

    delete app.session.uid;
    delete app.session.user;
    res.sendHeaders['X-Access-User'] = 0;
    req.status = 401;
    return false;
  }
}

async function adminPermission(req, res, domain, readonly) {
  if(!await checkUser(req, res))
    return false;

  if(app.session.user.is_admin)
    return true;
  else if(domain) {

    const dresult = await query('SELECT p.readonly FROM domains d, permissions p WHERE d.id=p.domain_id AND p.user_id=? AND d.name=? LIMIT 1', [app.session.uid, domain]);
    if(!dresult.length) {

      req.status = 404;
      req.content.message = txt('st404');
      return false;
    }

    if(!readonly || (readonly && dresult[0].readonly === 0))
      return true;
  }

  req.status = 403;
  req.content.message = txt('st403');
  return false;
}

// Get element or 404
async function getElm(req, res, sql, id, r) {
  const result = await dbQuery(req, res, sql, id);
  if(result && result.length) {

    if(r)
      return result[0];
    else
      req.content = result[0];

  } else {

    req.status = 404;
    req.content.message = txt('st404');
  }
}

// Tiny text function
function txt(code) {
  return texts(code, app.session.lang);
}

// Main
const app = backserver({ipv6:		cfg.protocol_ipv6,
			url:		cfg.backend_url,
			cert:		cfg.backend_cert,
			key:		cfg.backend_key,
			token:		cfg.backend_token,
			userfield:	'uid',
			before:		middleware,
			messages:	{missing: texts('missing'), login: texts('st401')},
			inisession:	async function(session) { await iniSession(session); }
		})
		.on('listening', address => console.log('JuNeDNS Backend', address))
		.on('error', err => addLog(err, 1));

// Users
app.post('/login', async (req, res) => {
  if(!app.checkParams({code: txt('code'), passwd: txt('passwd')}))
    return;

  const result = await getElm(req, res, 'SELECT * FROM users WHERE code=? LIMIT 1', req.body.code, true);
  if(result && result.passwd === crypto.scryptSync(req.body.passwd, cfg.backend_token.substring(0, 32), 32).toString('hex')) {

    app.session.uid = result.id;
    delete result.passwd;
    res.sendHeaders['X-Access-User'] = Buffer.from(JSON.stringify(result)).toString('base64');

    req.content = {types: types, expiry_token: app.expiry};
    if(log > 1)
      addLog('USER ' + req.body?.code?.substring(0, 20), 2, req.ip, 'LGN');

    return;
  }

  req.status = 403;
  req.content.message = txt('invalidpasswd');
  addLog('USER ' + req.body?.code?.substring(0, 20), 1, req.ip);
});

app.get('/login', async (req, res) => {
  if(!await checkUser(req, res))
    return;

  req.content = {types: types, expiry_token: app.expiry};
});

app.get('/ws_notices', (req, clients, options) => {
  options.notMe = true;
  req.content = {m: req.body.m, id: req.body.id}
});

app.get('/users', async (req, res) => {
  if(!await adminPermission(req, res))
    return;

  req.content.users = await dbQuery(req, res, 'SELECT id, code, name, is_admin FROM users ORDER BY code');
});

async function domains2db(req, id) {
  if(typeof req.body.domains !== 'object')
    return;

  await query('DELETE FROM permissions WHERE user_id=?', id);
  for(const i of req.body.domains) {

    const result = await query('SELECT * FROM domains WHERE id=?', i.domain_id);
    if(result.length)
      await query('INSERT INTO permissions SET user_id=?, domain_id=?, readonly=?', [id, i.domain_id, (i.readonly) ? 1 : 0]);
  }
}

app.post('/users', async (req, res) => {
  if(!await adminPermission(req, res) || !app.checkParams({code: txt('code'), passwd: txt('passwd')}))
    return;

  if(await dbQuery(req, res, 'INSERT INTO users SET code=?, passwd=?, name=?, is_admin=?', [req.body.code, crypto.scryptSync(req.body.passwd, cfg.backend_token.substring(0, 32), 32).toString('hex'), req.body.name, (req.body.is_admin) ? 1 : 0])) {

    await domains2db(req, await lastID());
    req.status = 201;
    req.content.message = txt('st201');
  }
});

app.get('/users/:id', async (req, res) => {
  if(!await adminPermission(req, res))
    return;

  req.content.user = await getElm(req, res, 'SELECT id, code, name, is_admin FROM users WHERE id=?', req.params.id, true);
  req.content.domains = await query('SELECT domain_id, readonly FROM permissions WHERE user_id=?', req.content.user.id);
});

app.post('/users/:id', async (req, res) => {
  if(!await adminPermission(req, res) || !app.checkParams({code: txt('code')}))
    return;

  if(await getElm(req, res, 'SELECT * FROM users WHERE id=?', req.params.id, true)) {

    if(req.body.passwd)
      await dbQuery(req, res, 'UPDATE users SET code=?, passwd=?, name=?, is_admin=? WHERE id=?', [req.body.code, crypto.scryptSync(req.body.passwd, cfg.backend_token.substring(0, 32), 32).toString('hex'), req.body.name, (req.body.is_admin) ? 1 : 0, req.params.id]);
    else
      await dbQuery(req, res, 'UPDATE users SET code=?, name=?, is_admin=? WHERE id=?', [req.body.code, req.body.name, (req.body.is_admin) ? 1 : 0, req.params.id]);

    await domains2db(req, req.params.id);
  }
});

app.delete('/users/:id', async (req, res) => {
  if(!await adminPermission(req, res))
    return;

  if(await getElm(req, res, 'SELECT * FROM users WHERE id=?', req.params.id, true))
    await dbQuery(req, res, 'DELETE FROM users WHERE id=?', req.params.id);
});

// Templates
app.get('/templates', async (req, res) => {
  if(await checkUser(req, res))
    req.content.templates = await dbQuery(req, res, 'SELECT t.*, COUNT(r.id) AS records FROM templates t LEFT JOIN template_records r ON t.id=r.template_id GROUP BY t.id ORDER BY t.name');
});

app.post('/templates', async (req, res) => {
  if(!await adminPermission(req, res) || !app.checkParams({name: txt('name')}))
    return;

  if(await dbQuery(req, res, 'INSERT INTO templates SET name=?, description=?, is_default=?', [req.body.name, req.body.description, (req.body.is_default) ? 1 : 0])) {

    req.status = 201;
    req.content.message = txt('st201');
  }
});

app.get('/templates/:id', async (req, res) => {
  if(!await adminPermission(req, res))
    return;

  req.content.template = await getElm(req, res, 'SELECT * FROM templates WHERE id=?', req.params.id, true);
  req.content.records = await dbQuery(req, res, 'SELECT id, name, type, content, ttl FROM template_records WHERE template_id=? ORDER BY type, name', req.params.id);
});

app.post('/templates/:id', async (req, res) => {
  if(!await adminPermission(req, res) || !app.checkParams({name: txt('name')}))
    return;

  if(await getElm(req, res, 'SELECT * FROM templates WHERE id=?', req.params.id, true))
    await dbQuery(req, res, 'UPDATE templates SET name=?, description=?, is_default=? WHERE id=?', [req.body.name, req.body.description, (req.body.is_default) ? 1 : 0, req.params.id]);
});

app.delete('/templates/:id', async (req, res) => {
  if(!await adminPermission(req, res))
    return;

  if(await getElm(req, res, 'SELECT * FROM templates WHERE id=?', req.params.id, true))
    await dbQuery(req, res, 'DELETE FROM templates WHERE id=?', req.params.id);
});

app.post('/templates/:id/records', async (req, res) => {
  if(!await adminPermission(req, res))
    return;

  const result = await getElm(req, res, 'SELECT * FROM templates WHERE id=?', req.params.id, true);
  if(!result)
    return;

  if(req.body.type && !types[req.body.type])
    req.body.type = '';

  if(!app.checkParams({name: txt('name'), type: txt('type'), content: txt('content')}))
    return;

  const ttl = parseInt(req.body.ttl, 10);

  await dbQuery(req, res, 'INSERT INTO template_records SET template_id=?, name=?, type=?, content=?' + ((ttl > 0) ? `, ttl=${ttl}` : ''), [result.id, req.body.name, req.body.type.toUpperCase(), req.body.content]);
  if(req.status === 200) {

    req.status = 201;
    req.content.message = txt('st201');
  }
});

app.post('/templates/:id/records/:rid', async (req, res) => {
  if(!await adminPermission(req, res))
    return;

  const result = await getElm(req, res, 'SELECT * FROM templates WHERE id=?', req.params.id, true);
  if(!result)
    return;

  const record = await getElm(req, res, 'SELECT * FROM template_records WHERE id=? AND template_id=?', [req.params.rid, result.id], true);
  if(!record)
    return;

  if(req.body.type && !types[req.body.type])
    req.body.type = '';

  if(!app.checkParams({name: txt('name'), type: txt('type'), content: txt('content')}))
    return;

  const ttl = parseInt(req.body.ttl, 10);

  await dbQuery(req, res, 'UPDATE template_records SET template_id=?, name=?, type=?, content=?' + ((ttl > 0) ? `, ttl=${ttl}` : '') + ' WHERE id=?', [result.id, req.body.name, req.body.type.toUpperCase(), req.body.content, record.id]);
});

app.delete('/templates/:id/records/:rid', async (req, res) => {
  if(!await adminPermission(req, res))
    return;

  const result = await getElm(req, res, 'SELECT * FROM templates WHERE id=?', req.params.id, true);
  if(!result)
    return;

  if(await getElm(req, res, 'SELECT * FROM template_records WHERE id=? AND template_id=?', [req.params.rid, result.id], true))
    await dbQuery(req, res, 'DELETE FROM template_records WHERE id=?', req.params.rid);
});

// Domains
app.get('/domains', async (req, res) => {
  if(!await checkUser(req, res))
    return;

  if(app.session.user.is_admin)
    req.content.domains = await dbQuery(req, res, 'SELECT d.id, d.name, d.nopunycode, LEFT(d.created, 10) AS created, 0 as readonly, COUNT(r.id) AS records FROM domains d LEFT JOIN records r ON d.id=r.domain_id GROUP BY d.id ORDER BY d.nopunycode');
  else
    req.content.domains = await dbQuery(req, res, 'SELECT d.id, d.name, d.nopunycode, LEFT(d.created, 10) AS created, p.readonly, COUNT(r.id) AS records FROM domains d LEFT JOIN records r ON d.id=r.domain_id, permissions p WHERE d.id=p.domain_id AND p.user_id=? GROUP BY d.id ORDER BY d.nopunycode', app.session.uid);
});

async function users2db(req, id) {
  if(typeof req.body.users !== 'object')
    return;

  await query('DELETE FROM permissions WHERE domain_id=?', id);
  for(const i of req.body.users) {

    const result = await query('SELECT * FROM users WHERE id=?', i.user_id);
    if(result.length)
      await query('INSERT INTO permissions SET user_id=?, domain_id=?, readonly=?', [i.user_id, id, (i.readonly) ? 1 : 0]);
  }
}

async function template2db(id, t) {
  await query('DELETE FROM records WHERE domain_id=?', id);
  const domain = await query('SELECT * FROM domains WHERE id=?', id);
  if(!domain.length)
    return;

  const d = domain[0].name;
  const result = await query('SELECT * FROM template_records WHERE template_id=?', t);
  for(const i of result) {

    if(i.type === 'AAAA' && !cfg.ipv6)
      continue;

    await query('INSERT INTO records SET domain_id=?, name=?, type=?, content=?, ttl=?', [id, i.name.replace('%d%', d), i.type, i.content.replaceAll('%d%', d).replaceAll('%m%', cfg.main_domain).replaceAll('%ip4%', cfg.ipv4).replaceAll('%ip6%', cfg.ipv6), i.ttl]);
  }
}

app.post('/domains', async (req, res) => {
  if(!await adminPermission(req, res) || !app.checkParams({name: txt('name')}))
    return;

  req.body.name = decodeURIComponent(escape(req.body.name));
  if(await dbQuery(req, res, 'INSERT INTO domains SET name=?, nopunycode=?, created=CURRENT_DATE', [(new URL(`https://${req.body.name}`)).hostname, req.body.name])) {

    const id = await lastID();
    await users2db(req, id);
    if(req.body.template)
      template2db(id, req.body.template);

    req.status = 201;
    req.content.message = txt('st201');
  }
});

app.get('/domains/:name', async (req, res) => {
  if(!await checkUser(req, res))
    return;

  if(app.session.user.is_admin) {

    req.content.domain = await getElm(req, res, 'SELECT id, name, nopunycode, LEFT(created, 10) AS created, 0 as readonly FROM domains WHERE name=?', req.params.name, true);
    req.content.users = await query('SELECT user_id, readonly FROM permissions WHERE domain_id=?', req.content.domain.id);

  } else
    req.content.domain = await getElm(req, res, 'SELECT d.id, d.name, d.nopunycode, LEFT(d.created, 10) AS created, p.readonly FROM domains d, permissions p WHERE d.id=p.domain_id AND p.user_id=? AND d.name=?', [app.session.uid, req.params.name], true);

  req.content.records = await query('SELECT id, name, type, content, ttl, disabled, no_ip FROM records WHERE domain_id=? ORDER BY type, name', req.content.domain.id);
});

app.post('/domains/:name', async (req, res) => {
  if(!await adminPermission(req, res, req.params.name, true))
    return;

  const result = await getElm(req, res, 'SELECT * FROM domains WHERE name=?', req.params.name, true);
  if(result) {

    if(app.session.user.is_admin)
      await users2db(req, result.id);

    if(req.body.template)
      template2db(result.id, req.body.template);
  }
});

app.delete('/domains/:name', async (req, res) => {
  if(!await adminPermission(req, res, req.params.name, true))
    return;

  if(await getElm(req, res, 'SELECT * FROM domains WHERE name=?', req.params.name, true))
    await dbQuery(req, res, 'DELETE FROM domains WHERE name=?', req.params.name);
});

function genNoIP() {
  return crypto.randomBytes(32).toString('base64').substring(0, 32).replaceAll('/', '0').replaceAll('+', '_');
}

app.post('/domains/:name/records', async (req, res) => {
  if(!await adminPermission(req, res, req.params.name, true))
    return;

  const result = await getElm(req, res, 'SELECT * FROM domains WHERE name=?', req.params.name, true);
  if(!result)
    return;

  if(result.name !== req.body.name.slice(-result.name.length)) // For security same domain name
    req.body.name = result.name;

  if(req.body.type && !types[req.body.type])
    req.body.type = '';

  if(!app.checkParams({name: txt('name'), type: txt('type'), content: txt('content')}))
    return;

  const ttl = parseInt(req.body.ttl, 10);

  await dbQuery(req, res, 'INSERT INTO records SET domain_id=?, name=?, type=?, content=?, disabled=?, no_ip=?' + ((ttl > 0) ? `, ttl=${ttl}` : ''), [result.id, req.body.name, req.body.type.toUpperCase(), req.body.content, (req.body.disabled) ? 1 : 0, (req.body.no_ip) ? genNoIP() : null]);
  if(req.status === 200) {

    req.status = 201;
    req.content.message = txt('st201');
  }
});

app.post('/domains/:name/records/:rid', async (req, res) => {
  if(!await adminPermission(req, res, req.params.name, true))
    return;

  const result = await getElm(req, res, 'SELECT * FROM domains WHERE name=?', req.params.name, true);
  if(!result)
    return;

  const record = await getElm(req, res, 'SELECT * FROM records WHERE id=? AND domain_id=?', [req.params.rid, result.id], true);
  if(!record)
    return;

  if(result.name !== req.body.name.slice(-result.name.length)) // For security same domain name
    req.body.name = '';

  if(req.body.type && !types[req.body.type])
    req.body.type = '';

  if(!app.checkParams({name: txt('name'), type: txt('type'), content: txt('content')}))
    return;

  const ttl = parseInt(req.body.ttl, 10);

  await dbQuery(req, res, 'UPDATE records SET name=?, type=?, content=?, disabled=?, no_ip=?' + ((ttl > 0) ? `, ttl=${ttl}` : '') + ' WHERE id=?', [req.body.name, req.body.type.toUpperCase(), req.body.content, (req.body.disabled) ? 1 : 0, ('no_ip' in req.body) ? ((req.body.no_ip) ? genNoIP() : null) : record.no_ip, record.id]);
});

app.delete('/domains/:name/records/:rid', async (req, res) => {
  if(!await adminPermission(req, res, req.params.name, true))
    return;

  const result = await getElm(req, res, 'SELECT * FROM domains WHERE name=?', req.params.name, true);
  if(!result)
    return;

  if(await getElm(req, res, 'SELECT * FROM records WHERE id=? AND domain_id=?', [req.params.rid, result.id], true))
    await dbQuery(req, res, 'DELETE FROM records WHERE id=?', req.params.rid);
});

app.get('/noip/:token', async (req, res) => {
  const result = await getElm(req, res, 'SELECT * FROM records WHERE no_ip=?', req.params.token, true);
  if(result) {

    await dbQuery(req, res, 'UPDATE records SET content=? WHERE id=?', [req.ip, result.id]);
    if(log > 1)
      addLog('TOKEN ' + req.params.token.substring(0, 10), 2, req.ip, 'NOI');

  } else
    addLog('NOIP ' + req.params.token.substring(0, 20), 1, req.ip);
});

app.post('/api/:apikey/:domain', async (req, res) => {
  if(cfg.backend_api && cfg.backend_apikey && cfg.backend_apikey === req.params.apikey && app.checkParams({name: txt('name'), type: txt('type'), content: txt('content')})) {

    const result = await getElm(req, res, 'SELECT * FROM domains WHERE name=?', req.params.domain, true);
    if(result) {

      const record = query('SELECT * FROM records WHERE domain_id=? AND name=?', [result.id, req.body.name, req.body.type]);
      if(record.length)
	await dbQuery(req, res, 'UPDATE records SET content=? WHERE id=?', [req.body.content, record[0].id]);
      else
	await dbQuery(req, res, 'INSERT INTO records SET domain_id=?, name=?, type=?, content=?, ttl=60', [result.id, req.body.name, req.body.type, req.body.content]);

      if(log > 1)
	addLog('APIKEY ' + req.params.apikey.substring(0, 10), 2, req.ip, 'API');

      return;
    }
  }

  addLog('APIKEY ' + req.params.apikey.substring(0, 20), 1, req.ip);
});

app.delete('/api/:apikey/:name/:type', async (req, res) => {
  if(cfg.backend_api && cfg.backend_apikey && cfg.backend_apikey === req.params.apikey) {

    const result = await getElm(req, res, 'SELECT * FROM records WHERE name=? AND type=?', [req.params.name, req.params.type], true);
    if(result)
      await query('DELETE FROM records WHERE id=?', result.id);

  } else
    addLog('APIKEY ' + req.params.apikey.substring(0, 20) + ` DEL ${req.params.name}`, 1, req.ip);
});

app.createServer();
