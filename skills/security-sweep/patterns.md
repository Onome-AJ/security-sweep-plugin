# Security Sweep — Detection Patterns Reference

This file contains all regex patterns and file-type mappings used by the security sweep skill. Patterns are organized by scan module.

---

## Section 1: SECRETS

### 1.1 High-Confidence API Keys (Specific Formats)

These have distinctive prefixes/formats with very low false-positive rates.

| Secret Type | Regex | Severity |
|---|---|---|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` | CRITICAL |
| AWS Temporary Key | `ASIA[0-9A-Z]{16}` | CRITICAL |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` | CRITICAL |
| GitHub OAuth | `gho_[A-Za-z0-9]{36}` | CRITICAL |
| GitHub App | `ghu_[A-Za-z0-9]{36}` | CRITICAL |
| GitHub Server | `ghs_[A-Za-z0-9]{36}` | CRITICAL |
| GitHub Refresh | `ghr_[A-Za-z0-9]{36}` | CRITICAL |
| Slack Bot Token | `xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}` | CRITICAL |
| Slack User Token | `xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32}` | CRITICAL |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` | HIGH |
| Stripe Live Secret | `sk_live_[0-9a-zA-Z]{24,}` | CRITICAL |
| Stripe Live Pub | `pk_live_[0-9a-zA-Z]{24,}` | MEDIUM |
| Stripe Restricted | `rk_live_[0-9a-zA-Z]{24,}` | CRITICAL |
| SendGrid Key | `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}` | CRITICAL |
| Twilio Key | `SK[0-9a-fA-F]{32}` | HIGH |
| Square Access | `sq0atp-[0-9A-Za-z\-_]{22}` | CRITICAL |
| Square OAuth | `sq0csp-[0-9A-Za-z\-_]{43}` | CRITICAL |
| Mailgun Key | `key-[0-9a-zA-Z]{32}` | HIGH |
| npm Token | `npm_[A-Za-z0-9]{36}` | CRITICAL |
| PyPI Token | `pypi-[A-Za-z0-9_-]{50,}` | CRITICAL |
| Shopify Access | `shpat_[a-fA-F0-9]{32}` | HIGH |
| Discord Bot | `[MN][A-Za-z\d]{23,}\.[\\w-]{6}\.[\\w-]{27}` | CRITICAL |
| Facebook Token | `EAACEdEose0cBA[0-9A-Za-z]+` | HIGH |
| OpenAI Key | `sk-[A-Za-z0-9]{20,}` | CRITICAL |
| OpenAI Project Key | `sk-proj-[A-Za-z0-9\-_]{40,}` | CRITICAL |
| Anthropic Key | `sk-ant-[A-Za-z0-9\-_]{40,}` | CRITICAL |
| HuggingFace Token | `hf_[A-Za-z0-9]{34}` | HIGH |

### 1.2 Private Keys

Search for these exact strings. Severity: CRITICAL.

```
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN DSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
-----BEGIN PRIVATE KEY-----
```

### 1.3 Database Connection Strings

| Type | Regex | Severity |
|---|---|---|
| PostgreSQL | `postgres(ql)?://[^:]+:[^@]+@[^\s]+` | CRITICAL |
| MySQL | `mysql://[^:]+:[^@]+@[^\s]+` | CRITICAL |
| MongoDB | `mongodb(\+srv)?://[^:]+:[^@]+@[^\s]+` | CRITICAL |
| Redis (auth) | `redis://:[^@]+@[^\s]+` | CRITICAL |
| MSSQL | `Server=.*Password=` | CRITICAL |
| JDBC | `jdbc:\w+://[^:]+:[^@]+@` | CRITICAL |

### 1.4 Generic Secret Patterns (Context-Dependent)

Use these with contextual keywords. Medium confidence — verify with `Read` before flagging as HIGH.

```
(api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9]{16,}["']
(secret[_-]?key|secretkey)\s*[:=]\s*["'][A-Za-z0-9]{16,}["']
(access[_-]?token|accesstoken)\s*[:=]\s*["'][A-Za-z0-9]{16,}["']
(client[_-]?secret|clientsecret)\s*[:=]\s*["'][A-Za-z0-9]{16,}["']
(encryption[_-]?key|encryptionkey)\s*[:=]\s*["'][A-Za-z0-9]{16,}["']
(jwt[_-]?secret|JWT_SECRET)\s*[:=]\s*["'][^"']{8,}["']
```

### 1.5 Password in URL

```
[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}
```

### 1.6 Env Fallback with Hardcoded Default

```
(os\.environ|process\.env|ENV)\[?.*\]?\s*\|\|\s*["'][A-Za-z0-9]{16,}
\.get\s*\(\s*["']\w+["']\s*,\s*["'][A-Za-z0-9]{16,}["']\)
```

### 1.7 Files That Should Never Be Committed

Check for existence of these via Glob:
```
**/.env
**/.env.local
**/.env.production
**/.env.staging
**/*.pem
**/*.key
**/*.p12
**/*.pfx
**/*.jks
**/*.keystore
**/id_rsa
**/id_dsa
**/id_ecdsa
**/id_ed25519
**/.netrc
**/.htpasswd
**/.pgpass
**/credentials.json
**/service-account*.json
**/.dockercfg
```

---

## Section 2: INJECTION

### 2.1 SQL Injection

File types: `*.py, *.js, *.ts, *.java, *.php, *.rb, *.go, *.cs`

**Python:**
```
(execute|executemany)\s*\(\s*f["']
(execute|executemany)\s*\(.*\.format\(
(raw|extra)\(.*%s.*%
```

**JavaScript/TypeScript:**
```
(query|execute)\s*\(\s*['"`].*\+\s*
(query|execute)\s*\(\s*`.*\$\{
\.raw\s*\(\s*`.*\$\{
```

**Java:**
```
(executeQuery|executeUpdate|execute)\s*\(.*\+
Statement.*execute.*\+
createQuery\(.*\+
```

**PHP:**
```
(mysql_query|mysqli_query)\s*\(.*\$
```

**Go:**
```
(Query|Exec|QueryRow)\(.*fmt\.Sprintf
```

### 2.2 Cross-Site Scripting (XSS)

File types: `*.js, *.ts, *.jsx, *.tsx, *.vue, *.html, *.php, *.erb, *.ejs`

```
\.innerHTML\s*=
\.outerHTML\s*=
document\.write\s*\(
document\.writeln\s*\(
dangerouslySetInnerHTML
v-html\s*=
bypassSecurityTrust
\{\{\{.*\}\}\}
\{!!.*!!\}
\|safe
<%\-.*%>
html_safe
```

### 2.3 Command Injection

File types: `*.py, *.js, *.ts, *.java, *.rb, *.php, *.go`

**Python:**
```
os\.system\s*\(
os\.popen\s*\(
subprocess\..*shell\s*=\s*True
commands\.(getoutput|getstatusoutput)\s*\(
```

**JavaScript/Node.js:**
```
child_process.*exec\s*\(
exec\s*\(\s*['"`].*\$\{
execSync\s*\(
eval\s*\(
new\s+Function\s*\(
```

**Java:**
```
Runtime\.getRuntime\(\)\.exec\s*\(.*\+
ProcessBuilder.*\+
```

**Ruby:**
```
system\s*\(.*\#\{
`.*\#\{
IO\.popen\s*\(
```

**PHP:**
```
(exec|system|passthru|shell_exec|popen|proc_open)\s*\(.*\$
```

### 2.4 SSRF

```
(fetch|axios\.\w+|http\.get|https\.get)\s*\(.*req\.(query|body|params)
requests\.(get|post|put|delete)\s*\(.*req\.(args|form|json|data)
new\s+URL\s*\(.*request\.getParameter
```

### 2.5 Insecure Deserialization

```
pickle\.(load|loads)\s*\(
yaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)
yaml\.unsafe_load\s*\(
ObjectInputStream\s*\(
BinaryFormatter
Marshal\.load\s*\(
unserialize\s*\(.*\$
```

### 2.6 Path Traversal

```
(open|readFile|readFileSync|createReadStream)\s*\(.*req\.(query|body|params)
os\.path\.join\s*\(.*request\.(GET|POST|args|form)
fs\.\w+\s*\(.*req\.(query|body|params)
new\s+File\s*\(.*request\.getParameter
(include|require|include_once|require_once)\s*\(.*\$_(GET|POST|REQUEST)
```

---

## Section 3: AUTH

### 3.1 JWT Misuse

```
algorithm.*none
jwt\.decode\(.*verify\s*=\s*False
jwt\.decode\(.*algorithms\s*=\s*\[["']none
jwt\.decode\(.*options.*ignoreExpiration.*true
jwt\.encode\(.*["'](secret|password|123|key|changeme)["']
JWT_SECRET\s*[:=]\s*["'](secret|password|changeme|key123)
localStorage\.setItem\(.*token
sessionStorage\.setItem\(.*token
```

### 3.2 Weak Password Handling

```
(md5|MD5)\(.*password
(sha1|SHA1)\(.*password
sha256\(.*password
MIN_PASSWORD_LENGTH\s*=\s*[1-7]
```

### 3.3 Insecure Session/Cookie Config

```
(httponly|HttpOnly)\s*[:=]\s*(false|False|0)
(secure|Secure)\s*[:=]\s*(false|False|0)
samesite\s*[:=]\s*["']none["']
```

### 3.4 Broken Access Control

```
(isAdmin|is_admin|role|userRole).*localStorage
req\.(body|query|params)\.(role|admin|isAdmin)
\.findByIdAndUpdate\(req\.params
\.findByIdAndDelete\(req\.params
```

---

## Section 4: CONFIG

### 4.1 CORS Misconfiguration

```
Access-Control-Allow-Origin.*\*
(cors|CORS).*origin.*\*
(cors|CORS).*origin.*true
CORS_ALLOW_ALL_ORIGINS\s*=\s*True
CORS_ORIGIN_ALLOW_ALL\s*=\s*True
cors\(\)
@CrossOrigin
```

### 4.2 Debug Mode Enabled

```
DEBUG\s*=\s*True
app\.debug\s*=\s*True
FLASK_DEBUG\s*=\s*1
FLASK_ENV\s*=\s*development
android:debuggable="true"
```

### 4.3 Dangerous CSP/Headers

```
Content-Security-Policy.*unsafe-inline
Content-Security-Policy.*unsafe-eval
X-Frame-Options.*ALLOWALL
```

### 4.4 Exposed Debug/Admin Endpoints

```
(route|path|get|post)\s*\(\s*["']/?(debug|_debug|phpinfo|server-info|server-status)
/actuator
/graphiql
```

### 4.5 Insecure TLS

```
verify\s*=\s*False
CERT_NONE
rejectUnauthorized\s*[:=]\s*false
InsecureSkipVerify\s*[:=]\s*true
TrustAllCerts|AllowAllHostnames
(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)
```

### 4.6 Docker Security

File types: `Dockerfile, docker-compose.yml, docker-compose.yaml`

```
FROM.*:latest
USER\s+root
RUN.*chmod\s+777
COPY.*\.env
(ARG|ENV).*(PASSWORD|SECRET|KEY|TOKEN)
--privileged
RUN.*(curl|wget).*\|.*sh
EXPOSE\s+(22|23|3389|5900)\b
```

### 4.7 Kubernetes / Terraform

File types: `*.yaml, *.yml, *.tf, *.hcl`

```
privileged:\s*true
hostNetwork:\s*true
hostPID:\s*true
allowPrivilegeEscalation:\s*true
runAsUser:\s*0
(acl|access)\s*=\s*["']public
cidr_blocks\s*=\s*\[["']0\.0\.0\.0/0["']\]
```

---

## Section 5: AI-SPECIFIC

### 5.1 Hardcoded AI API Keys

```
openai\.api_key\s*=\s*["']sk-
anthropic\.api_key\s*=\s*["']sk-ant-
(OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*[:=]\s*["']sk-
(HUGGING_FACE_TOKEN|HF_TOKEN)\s*[:=]\s*["']hf_
```

### 5.2 Prompt Injection Vectors

```
f["'].*system.*\{.*user_input
f["'].*\{.*request\.(body|query|params)
(messages|prompt).*\+\s*.*input
```

### 5.3 Executing LLM Output

```
eval\(.*completion|response|output|result.*\)
exec\(.*completion|response|output|result.*\)
innerHTML.*completion|response|output
```

### 5.4 Excessive Agent Permissions

```
(tools|functions).*\b(exec|eval|system|rm|delete|drop|sudo)\b
```

---

## Section 6: MOBILE

### 6.1 Android

File types: `*.java, *.kt, AndroidManifest.xml, *.gradle`

```
android:usesCleartextTraffic="true"
android:allowBackup="true"
android:exported="true"
SharedPreferences.*MODE_WORLD_READABLE
SharedPreferences.*MODE_WORLD_WRITEABLE
getSharedPreferences.*(password|token|secret|key)
TrustAllCerts|AllowAllHostnames
X509TrustManager.*checkServerTrusted.*\{\s*\}
ALLOW_ALL_HOSTNAME_VERIFIER
SecureRandom.*setSeed
```

### 6.2 iOS

File types: `*.swift, *.m, *.plist`

```
NSAllowsArbitraryLoads.*true
NSExceptionAllowsInsecureHTTPLoads
NSUserDefaults.*(password|token|secret|key)
UserDefaults\.standard\.set.*(password|token|secret)
CCCrypt.*kCCAlgorithmDES
```

### 6.3 Flutter/Dart

File types: `*.dart`

```
SharedPreferences.*(password|token|secret|key)
http://(?!localhost|127\.0\.0\.1)
```

---

## Section 7: DATA EXPOSURE

### 7.1 PII in Logs

```
(log|logger|console)\.\w+\(.*password
(log|logger|console)\.\w+\(.*secret
(log|logger|console)\.\w+\(.*token
(log|logger|console)\.\w+\(.*credit.?card
(log|logger|console)\.\w+\(.*ssn
(log|logger|console)\.\w+\(.*api.?key
(log|logger|console)\.\w+\(.*req\.body
print\(.*password|token|secret|api.?key
```

### 7.2 Sensitive Data in URLs

```
\?(.*&)*(password|token|secret|api_key|apikey)=
```

### 7.3 Plaintext HTTP to External Hosts

```
http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)
```

### 7.4 Weak Cryptography

```
(md5|sha1|MD5|SHA1)\s*[.(]
(DES|RC4|Blowfish)\b
\bECB\b
```

### 7.5 Error Handling (Information Leakage)

```
except:\s*$
except\s+Exception\s*:.*pass
catch\s*\(\s*\)\s*\{[\s]*\}
(res|response)\.(send|json)\(.*err\.(stack|message)
traceback\.(print_exc|format_exc)
```
