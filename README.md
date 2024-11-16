<p align="center">
  <a href="https://github.com/EduardoRuizM/junedns-backend"><img src="logo.png" title="JuNeDNS Backend" width="570" height="300"></a>
</p>
<h1 align="center">
  <a href="https://github.com/EduardoRuizM/junedns-backend">EduardoRuizM/junedns-backend</a>
</h1>
<p align="center">
  Dataclick Olimpo <a href="https://github.com/EduardoRuizM/junedns-backend">☀️JuNeDNS Backend</a>
  Safe, Lightweight and Full DNS Server ideal for single or hosting servers
</p>

# [☀️JuNeDNS Backend](https://github.com/EduardoRuizM/junedns-backend "JuNeDNS Backend")
## 🌐 Backend for [JuNeDNS Server](https://github.com/EduardoRuizM/junedns-server "JuNeDNS Server")

JuNeDNS is a lightweight DNS server and backend created in Node.js with a fully functionality and easy installation and use. With templates to easily create domain zones.

# Author
[Eduardo Ruiz](https://github.com/EduardoRuizM) <<eruiz@dataclick.es>>

# JuNe / JUst NEeded Philosophy
1. **Source code using less code as possible**
  So you can understand code and find bugs easier.
2. **Few and optimized lines is better**
  Elegant design.
3. **Avoid external dependencies abuse/bloated, and possible third-party bugs**
  Less files size, better and faster to the interpreter.
4. **Clear and useful documentation with examples and without verbose**
  Get to the point.
5. **Avoid showing unsolicited popups, notifications or messages in frontend**
  For better User eXperience.
6. **Simple UI**, without many menus/options and with few clicks to get to sites.
7. Consequences of having a lot of code (and for simple things): Having to work and search through many files and folders with a lot of wasted time, successive errors due to missing unknown files, madness to move a code to another project, errors due to recursive dependencies difficult to locate, complexity or impossibility to migrate to new versions, unfeasibility to follow the trace with so much code, risk of new errors if the functionality is extended, problems not seen at the first sight, general slowness in the whole development due to excessive and unnecessary code.

# Installation
### 1. Install and configure [JuNeDNS Server](https://github.com/EduardoRuizM/junedns-server "JuNeDNS Server")

### 2. Add tables to JuNeDNS Server database from [mysql-backend.sql](./mysql-backend.sql "mysql-backend.sql")
Add/Combine with existent MySQL/MariaDB **JuNeDNS Server** database using `mysql-backend.sql`
For templates, users and permissions functionality.

### 3. Create config file
File **junedns.conf** used by JuNeDNS Server and JuNeDNS Backend, be sure `backend_*` variables are setted.
```
...

// For backend
backend_url=http://localhost:9053
backend_cert=
backend_key=
backend_api=false
```
Changes requires restart JuNeDNS Backend / You need root privileges for installation.

At the very first run it will be created for session token and encrypt users passwords in database `backend_token=PRIVATE_KEYPAIR`

- **🐧Linux:** For security reasons limit file access with `chmod 600 junedns.conf`

Use **backend_cert / backend_key** for SSL (Let´s Encrypt) certificates path if you want HTTPS, and remember to set URL without port `backend_url=https://mybackend.tld`
Or maybe you prefer to use HTTP and proxy HTTPS with Nginx:
```
server {
	listen		443 ssl;
	listen		[::]:443 ssl; #http3?
	server_name	mybackend.tld;

	ssl_certificate		ACME_PATH/mydomain.tld/fullchain.cer;
	ssl_certificate_key	ACME_PATH/mydomain.tld/mydomain.tld.key;
	ssl_protocols			TLSv1.2 TLSv1.3;

	location / {
		proxy_set_header	X-Forwarded-For $remote_addr;
		proxy_set_header	Host $http_host;
		proxy_pass		http://127.0.0.1:9053;
	}
}
```

### 4 Running
Run JuNeDNS Backend using Node.js with source code or from binary:

#### 4.1 Running from Node.js with source code
Download or clone this repository.
Install dependencies `npm install` (JuNe 1 dependence: MySQL).

**Requirements** [node.js](https://nodejs.org) and [Node Package Manager](https://www.npmjs.org) (NPM).

- **Running from command line** (for example to debug)
-`node backend.js` or `npm start`

- **Running as service**

  - **🐧Linux:**
	- Use same JuNeDNS Server config file **junedns.conf**, you could create a symbolic link `ln -s /etc/junedns/junedns.conf /etc/junedns_backend/junedns.conf`
	- Create or copy Systemctl service `junedns-backend.service` in folder `/etc/systemd/system` or `/usr/lib/systemd/system` use ExecStart Source code execution line and adjust path if necessary.
	- Enable and start service `systemctl enable junedns-backend.service && systemctl start junedns-backend.service` check if running `systemctl status junedns-backend.service`

  - **🪟 Windows:**
    - Use same JuNeDNS Server config file **junedns.conf** and set correctly PATHs, you could create a symbolic link:
	`mklink "JuNeDNS_PATH\junedns.conf" "JuNeDNS_Backend_PATH\junedns.conf"`
    - Create service `sc create "JuNeDNS Backend" binPath="NodeJS_PATH\node JuNeDNS_Backend_PATH\backend.js"` start with `net start "JuNeDNS Backend"`

#### 4.2 Running from binaries (x64 bits)
Download and decompress your version: [🐧Linux](https://drive.google.com/file/d/1trMw2La5ctz45J8D1q9zw7ficMR4gFGs/view?usp=sharing "Linux") (20 Mb), [🪟 Windows](https://drive.google.com/file/d/1JBNyxFWd30J9pFb5wPX-dfh99A3KKUUu/view?usp=sharing "Windows") (17 Mb) or [🍎MacOS](https://drive.google.com/file/d/19kUNRZ6_1Cs-M5Nx0FldoJ6qKrDKNgBQ/view?usp=sharing "MacOS") (20 Mb).
Create [junedns.conf](./junedns.conf "junedns.conf")

- **Running from command line** (for example to debug with **log=3**)
-`./junedns-backend` or `junedns-backend`

- **Running as service**

  - **🐧Linux:**
    - Use same JuNeDNS Server path `/etc/junedns` and copy file in it.
    - Add executable permission `chmod +x /etc/junedns/junedns-backend`
	- Use same JuNeDNS Server config file **junedns.conf**
	- Create or copy Systemctl service `junedns-backend.service` in folder `/etc/systemd/system` or `/usr/lib/systemd/system` use ExecStart Binary execution line and adjust path if necessary.
	- Enable and start service `systemctl enable junedns-backend.service && systemctl start junedns-backend.service` check if running `systemctl status junedns-backend.service`

  - **🪟 Windows:**
    - Use same JuNeDNS Server path `C:\Users\[USER]\AppData\Roaming\JuNeDNS` and copy file in it.
    - Use same JuNeDNS Server config file **junedns.conf** in `C:\Users\[USER]\AppData\Roaming\JuNeDNS\junedns.conf`
    - Create service `sc create "JuNeDNS Backend" binPath="C:\Users\[USER]\AppData\Roaming\JuNeDNS\junedns-backend.exe"` start with `net start "JuNeDNS Backend"`

**🐧Linux:** Uncomment the ExecStart line you need for `junedns-backend.service`
```
[Unit]
Description=JuNeDNS Backend
After=network.target

[Service]
Type=simple
# Select only 1 ExecStart
#ExecStart=/etc/junedns/junedns-backend									#Binary execution
#ExecStart=/usr/bin/node /etc/junedns_backend/backend.js		#Source code execution

Restart=always
TimeoutStartSec=0

[Install]
WantedBy=default.target
```

### 5 Create admin user
Create the admin user to login and first steps, using createuser param in command line:
`node backend.js createuser USER PASSWORD`

# Endpoints
- JSON Content-Type requests.
- POST variables in BODY in JSON format.
- You can send `lang` GET parameter for language `/login?lang=es` just when changed, token updated.
- Returns variables in JSON.
- Token must be in header `x-access-token` except for login, noip or API.
- Users/templates management or create/delete domains only if current user `is_admin=1`
- Domain and Records changes only if `users.is_admin=1` or `permissions.readonly=0`

| Endpoint | Action | Method | POST Variables | Return variables |
| --- | --- | :---: | --- | --- |
| **/login** | Login user (all users) | POST | user, passwd | user, types |
| **/users** | Retrieve users | GET | - | users array |
| **/users** | Create user | POST | code, passwd, name, is_admin, domains | - |
| **/users/:id** | Get user | GET | - | - |
| **/users/:id** | Change user | POST | code, passwd, name, is_admin, domains | - |
| **/users/:id** | Delete user | DELETE | - | - |
| **/templates** | Retrieve templates with records count | GET | - | templates array |
| **/templates** | Create template | POST | name, description, is_default | - |
| **/templates/:id** | Get template | GET | - | - |
| **/templates/:id** | Change template | POST | name, description, is_default, records | - |
| **/templates/:id** | Delete template | DELETE | - | - |
| **/templates/:id/records** | Create template record | POST | name, type, content, ttl, prio | - |
| **/templates/:id/records/:rid** | Change template record | POST | name, type, content, ttl, prio | - |
| **/templates/:id/records/:rid** | Delete template record | DELETE | - | - |
| **/domains** | Retrieve domains with records count (all users) | GET | - | domains array (according permissions) |
| **/domains** | Create domain | POST | name, template, users | - |
| **/domains/:name** | Get domain | GET (all users) | - | domain and records |
| **/domains/:name** | Change domain template | POST | template, users | - |
| **/domains/:name** | Delete domain | DELETE | - | - |
| **/domains/:name/records** | Create record | POST | name, type, content, ttl, prio, disabled, no_ip | - |
| **/domains/:name/records/:rid** | Change record | POST | name, type, content, ttl, prio, disabled, no_ip | - |
| **/domains/:name/records/:rid** | Delete record | DELETE | - | - |
| **/noip/:token** | Change No-IP value | GET | - | - |
| **/api/:apikey/:domain** | Create/change record from API | POST | name, type, content | - |
| **/api/:apikey/:name/:type** | Delete record from API | DELETE | - | - |

[JuNeDNS No-IP](https://github.com/EduardoRuizM/junedns-noip "JuNeDNS No-IP") uses **/noip/:token** endpoint to update IP value.
**/api/:apikey/...** API endpoints for Let´s Encrypt or other service you need.

##### Definition of managements fields and types (if bool then value 0 or 1).
Required fields are not, for POST variables if default value.

#### User fields
| Field | Type | Required | Default | Definition |
| --- | :---: | :---: | :---: | --- |
| **id** | Integer | - | - | User Id |
| **code** | String | ✔ | - | User code |
| **passwd** | String | ✔ | - | User password |
| **name** | String | - | - | User name |
| **is_admin** | Bool | ✔ | 0 | User is admin (for users or full management) |
| **domains** | Array | - | - | For no-admin users, for create/change actions with domains access and if readonly |
domains sample `[{"domain_id": 1, "readonly": 0}, {"domain_id": 3, "readonly": 1}]`

#### Domain fields
| Field | Type | Required | Default | Definition |
| --- | :---: | :---: | :---: | --- |
| **id** | Integer | - | - | Domain Id |
| **name** | String | ✔ | - | Domain name in Punycode |
| **nopunycode** | String | - | - | Domain name |
| **template** | Integer | - | 1 | Template to use to create zone |
| **users** | Array | - | - | For no-admin users, for create/change actions with users access and if readonly |
users **Only is taken if admin user**, sample `[{"user_id": 1, "readonly": 0}, {"user_id": 3, "readonly": 1}]`

#### Record fields
| Field | Type | Required | Default | Definition |
| --- | :---: | :---: | :---: | --- |
| **id** | Integer | - | - | Record Id |
| **name** | String | ✔ | - | Record name in Punycode |
| **type** | String | ✔ | - | DNS type (from login available types) |
| **content** | String | ✔ | - | Record content |
| **ttl** | Integer | | 259200 | Record Time To Live / Expiry (seconds) |
| **prio** | Integer | - | - | Priority only for MX |
| **disabled** | Bool | ✔ | 0 | Record is disabled |
| **no_ip** | String | - | - | No-IP automatized token |

Although domain name is inside record name, for security reasons don´t allow users to change it and show it as read only (like Frontend does), JuNeDNS Server checks Root Zone with record, and JuNeDNS Backend parses this value to avoid spoofing.

#### Templates to insert predefined records automatically, management only for admin users
#### Template fields
| Field | Type | Required | Default | Definition |
| --- | :---: | :---: | :---: | --- |
| **id** | Integer | - | - | Template Id |
| **name** | String | ✔ | - | Template name |
| **description** | String | - | - | Template description |
| **is_default** | Bool | ✔ | 0 | Is default selected template for new domains |
| **records** | Array | - | - | Template records |

#### Template records fields
| Field | Type | Required | Default | Definition |
| --- | :---: | :---: | :---: | --- |
| **id** | Integer | - | - | Template record Id |
| **name** | String | ✔ | - | Template record name |
| **type** | String | ✔ | - | Template record type |
| **content** | String | ✔ | - | Template record content |
| **ttl** | Integer | | 259200 | Template record Time To Live / Expiry (seconds) |
| **prio** | Integer | - | - | Template record priority only for MX |

#### Wildcards used in template records (name or content)
Records in templates using wildcards that are replaced with real values:

| Wildcard | Description | Sample |
| :---: | --- | --- |
| %d% | Domain name | *mydomain.tld* |
| %m% | Main domain where NS point to, setted in config `main_domain` | *nsdomain.tld*  |
| %ip4% | IPv4 setted in config `ipv4` | *1.2.3.4*  |
| %ip6% | IPv6 setted in config `ipv6` ignored if not IPv6 | *i:want:an:ipv6:address:so:change:me*  |

Have a look to some template records as SOA or SPF to check that are correct values (ns1, info...).

### Predefined templates
Two templates to create domain DNS zones, you can create your owns in database tables:

| id | Name | Description | Default |
| ---: | --- | --- | :---: |
| 1 | **Default** | Normal DNS zone with MX on server | ✔ |
| 2 | **With Google Workspace** | DNS zone with MX for Google Workspace | - |

## HTTP status response
With translated JSON message as `message` variable in return BODY, or content response if 200:

| Status | Response | Sample message |
| :---: | --- | --- |
| 200 | Ok | - |
| 201 | Created | *Created* |
| 400 | Bad Request | *Already exists* |
| 401 | Unauthorized | *You must login* |
| 403 | Forbidden | *You have not permissions to create domains* |
| 404 | Not found | *Not found mydomain.tld* |

## 🏳Languages
Availables for `lang` GET parameter.
Help us to translate JuNeDNS in your language 📩 info@dataclick.es

| Code | Short code | Language |
| :---: | --- | --- |
| en-US | en | 🇬🇧 English |
| es-ES | es | 🇪🇸 Español |
| fr-FR | fr | 🇫🇷 Français |
| de-DE | de | 🇩🇪 Deutsch |
| it-IT | it | 🇮🇹 Italiano |
| pt-PT | pt | 🇵🇹 Português |
| zh-CN | ch | 🇨🇳 中文 |

First try ´code´ next ´Short code´ from *window.navigator.language* (default en-US)

## Types available on login
Return all available DNS records, with name and type (str, int8, int16, int32, ipv4, ipv6 or array).
Sample:
```
const types = {
	SOA: {primary: 'str', admin: 'str', serial: 'int32', refresh: 'int32', retry: 'int32', expiration: 'int32', minimum: 'int32'},
	 A: {address: 'ipv4'},
	 CAA: {flags: [0, 1], tag: ['issue', 'issuewild', 'iodef'], value: 'str'},
	 ...
};
```
## Permissions
*is_admin* per user, *readonly* per user+domain:

| Actions | is_admin=1 | is_admin=0, readonly=0 | is_admin=0, readonly=1 | is_admin=0 |
| --- | :---: |  :---: |  :---: |  :---: |
| Users/templates management | ✅ |  ❌ |  ❌ |  ❌ |
| Domains create/delete | ✅ |  ❌ |  ❌ |  ❌ |
| Domains list | ✅ |  ✅ |  ✅ |  ❌ |
| Records create/change/delete | ✅ |  ✅ |  ❌ |  ❌ |
| Records list | ✅ |  ✅ |  ✅ |  ❌ |

## Test
With **cURL** (you don´t need Postman):
- Login:
  `curl -v -X POST -H "Content-Type: application/json" -d "{\"user\": \"USER\", \"passwd\": \"\"}" http://localhost:9053/login`
- Create domain without template:
  `curl -v -X POST -H "Content-Type: application/json" -H "x-access-token: TOKEN" -d "{\"name\": \"mydomain.tld\", \"template\": 0}" http://localhost:9053/domains`
- Delete record 22 from domain mydomain.tld:
  `curl -v -X DELETE -H "Content-Type: application/json" -H "x-access-token: TOKEN" http://localhost:9053/domains/mydomain.tld/records/22`

# Logs
You can use `log` to share parameter with JuNeDNS Server or use `backend_log`
For security, maximum log size per file will be 50 Mb or truncate.

## Reading logs
Line formats in `junedns-backend.log` when `log=2` (or 3) in `junedns.conf`
- LGN = Login, NOI = No-IP, API, or ERR = Error.
  `yyyy-mm-dd hh:mm:ss [LGN|NOI|API|ERR] IP: <ip> message`
- Sample of login:
  `2024-01-01 09:45:05 [LGN] IP: <1.2.3.4> USER user`
- Sample of No-IP / API change request (token with 10 first chars):
  `2024-01-01 09:45:05 [NOI] IP: <1.2.3.4> TOKEN token`
  `2024-01-01 09:45:05 [API] IP: <1.2.3.4> APIKEY apikey`
- Error sample if log is not 0 in `junedns.conf` maybe `USER` if login:
  `2024-01-01 09:45:05 [ERR] IP: <1.2.3.4> USER user`
  `2024-01-01 09:45:05 [ERR] IP: <1.2.3.4> API api`
- ...or if No-IP request invalid:
  `2024-01-01 09:45:05 [ERR] IP: <1.2.3.4> NOIP token`
User or No-IP token will be truncated to 20 first characters due security.

## Rotate logs
**🐧Linux:** Add rotate log functionality and keep in mind that log file will be increase over time.
- Your could change log file path to `/var/log/junedns-backend.log` and changing *const flog* value in **backend.js**
- Create file `/etc/logrotate.d/junedns-backend` and set correctly JuNeDNS_PATH

```
JuNeDNS_PATH/junedns-backend.log {
        daily
        missingok
        rotate 4
        compress
        copytruncate
        create 600 root root
}
```

# Compile JuNeDNS Backend
Get executable compiled in folder **dist/** (x64 bits) for: 🐧Linux, 🪟 Windows and 🍎MacOS.
- Rename **package.json** to **package.bak.json**
- Then rename **package.compile.json** to **package.json** to use *Package your Node.js (pkg)*
- And run `npm run build` or by platform `npm run build-linux` (or build-win, build-macos)

# Let´s Encrypt
Using [acme.sh](https://github.com/acmesh-official/acme.sh "acme.sh") to create/renew SSL certificates for HTTPS, and create TXT domain challenge.
Different way to create/change record using Backend internal API with cURL, instead of dns_junedns.sh from JuNeDNS Server that uses MySQL/MariaDB client.
- Copy or replace **dns_junednsapi.sh** to folder `ACME_PATH/dnsapi`
- Be sure cURL installed on server `sudo apt install curl`
- Change `backend_api=true` in `junedns.conf` then restart and you see a new `backend_apikey` value.
- Add this API key and backend URL values to `ACME_PATH/account.conf`

```
JUNEDNSAPI_URL='http://localhost:9053'
JUNEDNSAPI_APIKEY='SAME_APIKEY_AS_junedns.conf_backend_apikey'
```
Then to create a new certificate:
`ACME_PATH/acme.sh --issue --dns dns_junednsapi -d "mydomain.tld" --server letsencrypt`

Let´s  Encrypt is free but only 3 months validity.
Add cron task to automatically renew SSL certificates:
`ACME_PATH/acme.sh --home "ACME_PATH" --renew-all --stopRenewOnError --server letsencrypt --cron`
Use --server letsencrypt to allow * wildcard domains (default ZeroSSL not supported).

✔️JuNeDNS Backend detects if certificates are renewed (different datetime) and restarts automatically.

## Fail2ban
If you want to prevent DDoS / brute force attacks you can use [Fail2ban](https://www.fail2ban.org "Fail2ban"), in case of login or No-IP.
- Set `log=2` in `junedns.conf`
- Create `/etc/fail2ban/jail.d/junednsbackend.conf`
```
[junednsbackend-iptables]
enabled = true
port = dns
filter = junednsbackendfilter
action = iptables[name=junednsbackend, port=9053, protocol=http]
logpath = /etc/junedns/junedns-backend.log
maxretry = 10
```
- Create `/etc/fail2ban/filter.d/junednsbackendfilter.conf`
```
[Definition]
failregex = ^.+ERR.+IP: <HOST>.+$
ignoreregex =
```
- Unban IP `fail2ban-client set junednsbackend-iptables unbanip 1.2.3.4`

## JuNe BackServer for tokens
When you create a client ↔ server system, now renamed backend ↔ frontend, you need a link between both for an identification.
This used to be done with a session token saved in a database table along the data as a JSON on the server (I mean, backend), and on the client (I mean, frontend) it´s saved as a cookie.
Now a token is made in a JSON with encrypted data, which is sent in the HTTP header each time by the frontend and verified by the backend.
JSONWebToken, a module of 1170 files, 21 folders and 1,6 MB... is used as standard, included it´s ´shhhhh´ secret. But with JuNe Token the same goal is achieved with a few lines of code.
A private key is generated and stored in `junedns.conf` if it was not already created `backend_token=` then a JSON is encoded with the data and the expiration of the token, and sent as HTTP header.
Frontend stores it in sessionStorage, and never sends by GET parameters to avoid relogin if back.

🗜 You can see that this code is just a few lines in 930 bytes, a 0,05% from JSONWebToken (that is x1800):
```
const crypto = require('crypto');

// Generate key pair to export to config
token = crypto.generateKeyPairSync('rsa', {modulusLength: 1024}).privateKey.export({type: 'pkcs1', format: 'der'}).toString('base64');

// Create public and private keys
const pubk = crypto.createPublicKey({key: Buffer.from(token, 'base64'), type: 'pkcs1', format: 'der'});
const prik = crypto.createPrivateKey({key: Buffer.from(token, 'base64'), type: 'pkcs1', format: 'der'});

// Session token variable
let session = {};

// Set header x-access-token an expiry 15 minutes
function setHeader(expiry = 900) {
  session._exp = Math.round((new Date()).getTime() / 1000) + expiry;
  return crypto.publicEncrypt({key: pubk, padding: crypto.constants.RSA_PKCS1_PADDING}, Buffer.from(JSON.stringify(session))).toString('base64');
}

// Get header if not expired
function getHeader(xhdr) {
  session = JSON.parse(crypto.privateDecrypt({key: prik, padding: crypto.constants.RSA_PKCS1_PADDING}, Buffer.from(xhdr, 'base64')).toString('utf-8'));
  if(session._exp < Math.round((new Date()).getTime() / 1000))
    session = {};
}
```
** What is safer? **
In database token system, it´s very complicated to discover the token, which would not exist for more than a few hours, and also brute force attacks can be controlled. In JSON token system if the private key is compromised, then it would be easier to perform spoofing.

## Included to make this project [JuNe BackServer](https://github.com/EduardoRuizM/june-backserver "JuNe BackServer")

# JuNeDNS Server & Frontend & No-IP

https://github.com/EduardoRuizM/junedns-server

https://github.com/EduardoRuizM/junedns-frontend

https://github.com/EduardoRuizM/junedns-noip

# Trademarks©️
**Dataclick Olimpo JuNeDNS**
- [Dataclick.es](https://www.dataclick.es "Dataclick.es") is a software development company since 2006.
- [Olimpo](https://www.dataclick.es/en/technology-behind-olimpo.html "Olimpo") is a whole solution software to manage all domains services such as hosting services and to create Webs in a server.
- JuNe / JUst NEeded Philosophy, available software and development solutions.
- [JuNeDNS](https://github.com/EduardoRuizM/junedns-server "JuNeDNS") is a part of Dataclick Olimpo domains management for DNS service, released to Internet community.
- Feel free to use JuNeDNS according MIT license respecting the brand and image logotype that you can use.

# Files
| File | Description |
| --- | --- |
| backend.js | JuNeDNS Backend main file, just **25 Kb** (JuNe Philosophy) |
| dns_junedns.sh | Let´s Encrypt API using cURL for acme.sh to create/renew SSL certificates |
| junedns.conf | Configuration file for JuNeDNS Server and Backend |
| junedns-backend.service | Systemctl service for Backend binary or source code execution |
| logo.png | JuNeDNS Backend Logo free to use |
| mysql-backend.sql | MySQL/MariaDB database to combine with JuNeDNS Server database |
| package.compile.json | package.json file to compile Backend binaries in folder **dist/** |
| package.json | Original Backend package.json |
| texts.js | Texts in languages |
| backserver.js | JuNe BackServer for routing and web token |
