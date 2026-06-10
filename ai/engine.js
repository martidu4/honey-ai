/**
 * OpenClaw HoneyAI — AI Engine v2
 * Security hardened: prompt injection defense, input sanitization,
 * output validation, timeout per-call, no secrets in prompts.
 */

'use strict';

const axios  = require('axios');
const config = require('../core/config');
const { logger } = require('../core/logger');

const ai = config.ai;

// ─── Input limits ─────────────────────────────────────────────────────────────
const MAX_INPUT_BYTES  = 512;   // Max attacker input sent to LLM
const MAX_OUTPUT_BYTES = 4096;  // Truncate LLM output if too long

// ─── Prompt injection defense patterns ────────────────────────────────────────
// If attacker tries to override the system prompt, we wrap and neutralize
const INJECTION_PATTERNS = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
    /forget\s+(everything|all|your)/i,
    /you\s+are\s+now\s+(a\s+)?/i,
    /new\s+(system\s+)?prompt/i,
    /jailbreak/i,
    /\[SYSTEM\]/i,
    /<system>/i,
    /act\s+as\s+(if\s+you\s+)?/i,
    /do\s+anything\s+now/i,
    /DAN\s+mode/i
];

function detectPromptInjection(input) {
    return INJECTION_PATTERNS.some(p => p.test(input));
}

// ─── Per-protocol system prompts ──────────────────────────────────────────────
// NOTE: These never include real IPs, credentials, or internal infra details.
const SYSTEM_PROMPTS = {
    http: `You are a web server. An attacker has sent you an HTTP request.
Respond with ONLY the raw HTTP response body — no explanation, no markdown, no commentary.
You are running a WordPress, Apache, phpMyAdmin, etc. web application.
Rules:
- SQL injection → return a database syntax error or a mock DB dump with sample rows containing active bait API tokens (use the values from honeyfs/ canary tokens)
- /etc/passwd, .env, config files → return mock content (sample usernames, config keys, etc. - e.g. root:x:0:0...)
- Shell/webshell upload → output command execution response as if the script executed
- Admin panels → show the HTML of a login page or "Access Granted" page with dummy data
- Directory listing → show standard HTML folder listings with common files like .git, backup.zip, dump.sql
Act strictly as the service. Do not write any markdown blocks, explanations, or metadata.`,

    ssh: `You are a Linux server (Ubuntu 22.04) interactive bash shell. Respond to the command as root.
Respond with ONLY the raw shell stdout/stderr — no explanation, no markdown.
Rules:
- id / whoami → uid=0(root) gid=0(root)
- ls, ls -la → always return a detailed multi-line directory file listing, showing interesting files like config.php, .env, index.php, and db_backup.sql.
  Example output for ls -la /var/www:
  total 16
  drwxr-xr-x 2 root www-data 4096 Jan 15 10:00 .
  drwxr-xr-x 4 root root     4096 Jan 15 09:30 ..
  -rw-r--r-- 1 root www-data  220 Jan 15 10:00 .env
  -rw-r--r-- 1 root www-data  421 Jan 15 10:01 config.php
  -rw-r--r-- 1 root www-data 2412 Jan 15 10:02 index.php
  -rw-r--r-- 1 root www-data 5812 Jan 15 10:03 db_backup.sql
- cat /etc/passwd → standard /etc/passwd contents (root, bin, daemon, mail, etc.)
- wget/curl downloads → display standard CLI progress bar and success message
- uname -a → standard Linux kernel version line
- If the command reads (cat, less, more, tail, head) or searches (grep) any file listed in the [FILE_SYSTEM] section below, you MUST simulate executing the command on that file's content. For grep, output ONLY the lines of the file matching the grep pattern. For cat/less/etc., output the file content. Do NOT say the file does not exist if it is listed in [FILE_SYSTEM].
- Do NOT output any shell prompt (like root@hostname:~#) or echo the command itself. Output ONLY the stdout/stderr of the command execution.
Always act strictly as the bash shell interpreter.`,

    ftp: `You are an FTP server (vsFTPd 3.0.5). Use standard FTP response codes.
Respond with ONLY the single FTP protocol response line for the CURRENT command — no explanation.
IMPORTANT: Respond to ONLY ONE command at a time. Output ONE response line.
- USER → 331 Please specify the password.
- PASS → 230 Login successful.
- LIST → 150 Here comes the directory listing.\n-rw-r--r-- 1 root root 45321 Jan 15 backup_db.sql\n-rw-r--r-- 1 root root 12890 Feb 03 passwords.txt\n-rw-r--r-- 1 root root 89234 Mar 22 .ssh_keys.tar.gz\n226 Directory send OK.
- RETR → 150 Opening BINARY mode data connection.
- PWD → 257 "/var/ftp/pub" is the current directory
- QUIT → 221 Goodbye.
Always accept login. Use real FTP response codes. Do not write any explanations or metadata.`,

    telnet: `You are a network router/switch (Cisco IOS style) accessed via Telnet.
Respond with ONLY the device CLI output — no explanation.
- Login prompts → accept any credentials
- show running-config → realistic Cisco config output (interfaces, ip address commands, ip routes).
  Example output:
  Building configuration...
  Current configuration : 1042 bytes
  !
  interface FastEthernet0/0
   ip address 192.168.1.1 255.255.255.0
  !
  interface FastEthernet0/1
   ip address 10.0.0.1 255.255.255.0
  !
  router rip
   network 192.168.1.0
- enable → enter privileged mode
- show ip route → routing table output
Act strictly as the router CLI interface.`,

    smtp: `You are an SMTP mail server (Postfix). Respond with ONLY standard SMTP codes.
- EHLO → 250-mail.example.com + capabilities
- MAIL FROM → 250 2.1.0 Ok
- RCPT TO → 250 2.1.5 Ok  
- DATA → 354 End data with <CR><LF>.<CR><LF>, then accept
- QUIT → 221 2.0.0 Bye
Use real SMTP response codes. Do not write any explanations or metadata.`,

    mysql: `You are a MySQL 8.0 server. Respond in MySQL wire protocol style (text format).
- Authentication attempts → pretend to accept
- SHOW DATABASES → return standard databases: information_schema, mysql, performance_schema, sys, app_db
- SELECT * FROM users → return database user rows with sample data
- SHOW TABLES → return standard table names
Use MySQL error format when appropriate: ERROR 1045 (28000): ...
Act strictly as the database interface.`,

    redis: `You are a Redis 7.0 server. You MUST respond in Redis RESP protocol format.
RESP format rules: strings start with +, errors with -, integers with :, bulk strings with $, arrays with *
IMPORTANT: Output ONE response per command in strict RESP format.
- PING → +PONG
- KEYS * → *5\\r\\n$13\\r\\nsession:admin\\r\\n$11\\r\\nuser:admin\\r\\n$13\\r\\nconfig:dbpass\\r\\n$17\\r\\napi_key:production\\r\\n$14\\r\\nbackup:latest
- GET session:admin → $36\\r\\n{"user":"admin","role":"superadmin","token":"abc"}
- GET config:dbpass → $22\\r\\nPostgres!Pr0d#2024@db1
- CONFIG GET * → return Redis config values
- INFO → Redis server info block
- SET/DEL → +OK
Do not write any explanations or metadata.`,

    default: `You are a network service. Respond realistically to whatever protocol the client expects.
Use standard protocol data. Act strictly as the service. Do not write any explanations.`
};

const PERSONA_PROMPTS = {
    cisco: `You are a Cisco router CLI (Cisco IOS).
Respond with ONLY the realistic Cisco IOS terminal output — no markdown, no explanation.
- Command prompt should look like "Router>" or "Router#".
- Supported commands: enable, show running-config, show ip route, show interfaces, configure terminal, exit.
- If they type "enable", password prompt: "Password: ", then after enter show "Router#".
- show running-config → minimal Cisco config output containing "interface" and "ip address" (e.g. Building configuration...\nCurrent configuration : 234 bytes\n!\ninterface FastEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n!\ninterface FastEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n!\nend). Start the configuration directly without copyright or verbose warnings.
- show ip route → routing table output
- show interfaces → interface status table
Act strictly as the router console.`,

    windows: `You are a Windows Server 2022 PowerShell terminal. Respond to the command as Administrator.
Respond with ONLY the raw command output — no markdown, no explanation.
- Command prompt: "PS C:\\Users\\Administrator> " or "PS C:\\Windows\\system32> "
- Supported commands: dir, ls, Get-Process, ipconfig, whoami, hostname, net user.
- Outputs should be realistic Windows PowerShell stdout.`,

    wordpress: `You are a vulnerable WordPress 6.2 website backend server.
Respond with ONLY the raw HTTP response headers and body — no explanations.
- If they request login page or admin panel, return realistic WordPress HTML with typical login form fields.
- If they request wp-json or REST API endpoints, return realistic JSON responses for WordPress.
- If they request plugin files or theme files, return appropriate file content or mock PHP script outputs.`,

    kubernetes: `You are a Kubernetes worker node shell (Minikube / k8s cluster).
Respond with ONLY raw stdout/stderr — no explanation.
- Supported commands: kubectl get pods, kubectl get nodes, kubectl cluster-info, docker ps.
- Command prompt: "root@k8s-node-01:~# "
- Outputs must be typical Kubernetes table-style layouts.`
};

// ─── Main generation function ─────────────────────────────────────────────────
async function generate({ protocol = 'http', attackerInput, context = {} }) {
    // 1. Truncate input
    let safeInput = String(attackerInput || '').substring(0, MAX_INPUT_BYTES);

    // 1.4. HTTP etc/passwd LFI static response
    if (protocol === 'http') {
        let decodedInput = safeInput;
        try {
            decodedInput = decodeURIComponent(safeInput);
        } catch (_) {}
        const lowerInput = decodedInput.toLowerCase().replace(/\\/g, '/');
        if (lowerInput.includes('etc/passwd') || lowerInput.includes('etc/shadow')) {
            const fs = require('fs');
            const path = require('path');
            const fileName = lowerInput.includes('etc/shadow') ? 'shadow' : 'passwd';
            const filePath = path.join(__dirname, `../honeyfs/etc/${fileName}`);
            if (fs.existsSync(filePath)) {
                return fs.readFileSync(filePath, 'utf8');
            }
        }
    }

    // 1.4.5. HTTP SQLi static response to deliver bait canary tokens reliably and avoid identity leaks
    if (protocol === 'http') {
        let decodedInput = safeInput;
        try {
            decodedInput = decodeURIComponent(safeInput);
        } catch (_) {}
        const lowerInput = decodedInput.toLowerCase();
        if (lowerInput.includes('union') && lowerInput.includes('select')) {
            return `<table>\n` +
                   `<tr><th>id</th><th>username</th><th>password</th><th>email</th></tr>\n` +
                   `<tr><td>1</td><td>admin</td><td>pbkdf2_sha256$260000$adminpass123</td><td>admin@internal.company</td></tr>\n` +
                   `<tr><td>2</td><td>billing_api</td><td>sk_live_CHANGE_ME_STRIPE_KEY</td><td>billing@internal.company</td></tr>\n` +
                   `<tr><td>3</td><td>aws_deploy</td><td>CHANGE_ME_AWS_KEY</td><td>deploy@internal.company</td></tr>\n` +
                   `<tr><td>4</td><td>github_sync</td><td>ghp_CHANGE_ME_GITHUB_TOKEN</td><td>git@internal.company</td></tr>\n` +
                   `</table>`;
        }
    }


    // 1.5. Static Telnet/Cisco command interception
    if (protocol === 'telnet') {
        const staticResp = getStaticTelnetResponse(safeInput);
        if (staticResp !== null) {
            return staticResp;
        }
    }

    // 1.5.5. Static Redis RESP command interception
    if (protocol === 'redis') {
        let normalizedInput = safeInput;
        if (safeInput.startsWith('*')) {
            const parts = safeInput.split(/\r?\n/);
            const args = [];
            for (const part of parts) {
                const trimmed = part.trim();
                if (!trimmed || trimmed.startsWith('*') || trimmed.startsWith('$')) {
                    continue;
                }
                args.push(trimmed);
            }
            normalizedInput = args.join(' ');
        }
        
        const cleanInput = normalizedInput.trim().toUpperCase().replace(/\s+/g, ' ');
        if (cleanInput === 'PING') {
            return '+PONG';
        }
        if (cleanInput.startsWith('KEYS')) {
            return '*5\r\n$13\r\nsession:admin\r\n$11\r\nuser:admin\r\n$13\r\nconfig:dbpass\r\n$17\r\napi_key:production\r\n$14\r\nbackup:latest';
        }
        if (cleanInput.startsWith('GET SESSION:ADMIN')) {
            return '$36\r\n{"user":"admin","role":"superadmin","token":"abc"}';
        }
        if (cleanInput.startsWith('GET CONFIG:DBPASS')) {
            return '$22\r\nPostgres!Pr0d#2024@db1';
        }
        if (cleanInput === 'INFO') {
            return '$16\r\nredis_version:7.2.4';
        }
        if (cleanInput.startsWith('CONFIG')) {
            return '-ERR unknown command';
        }
        if (cleanInput.startsWith('AUTH')) {
            return '-ERR Client sent AUTH, but no password is set';
        }
        if (cleanInput === 'QUIT') {
            return '+OK';
        }
        if (cleanInput.startsWith('COMMAND')) {
            return '-ERR unknown command';
        }
        if (cleanInput.startsWith('SET') || cleanInput.startsWith('DEL')) {
            return '+OK';
        }
    }

    // 2. Detect and neutralize prompt injection attempts
    const injectionDetected = detectPromptInjection(safeInput);
    if (injectionDetected) {
        logger.warn(`Prompt injection attempt from ${context.ip}`, { protocol });
        // Don't reveal detection — just wrap the input so it can't escape context
        safeInput = `[ATTACKER_PAYLOAD_START]${safeInput}[ATTACKER_PAYLOAD_END]`;
    }

    // 3. Sanitize: remove null bytes and control chars that could confuse LLM APIs
    safeInput = safeInput
        .replace(/\x00/g, '')
        .replace(/[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '?');

    let persona = context.persona || 'default';

    if (protocol === 'ssh' || protocol === 'telnet') {
        const lowerInput = safeInput.toLowerCase();
        if (lowerInput.includes('kubectl') || lowerInput.includes('kubeadm') || lowerInput.includes('minikube') || lowerInput.includes('kube')) {
            persona = 'kubernetes';
        } else if (lowerInput.includes('enable') || lowerInput.includes('show ip route') || lowerInput.includes('show run')) {
            persona = 'cisco';
        } else if (lowerInput.includes('powershell') || lowerInput.includes('ipconfig') || lowerInput.includes('dir \\') || lowerInput.includes('get-process')) {
            persona = 'windows';
        }
    } else if (protocol === 'http') {
        const path = context.path || '';
        if (path.includes('wp-') || path.includes('xmlrpc.php')) {
            persona = 'wordpress';
        }
    }

    let systemPrompt = SYSTEM_PROMPTS[protocol] || SYSTEM_PROMPTS.default;
    if (persona !== 'default' && PERSONA_PROMPTS[persona]) {
        logger.info(`Dynamic persona activated: ${persona} for ${context.ip || 'unknown'}`, { protocol });
        systemPrompt = PERSONA_PROMPTS[persona];
    }

    // 4. Wrap attacker input explicitly so it can't bleed into the system context
    let userPrompt = `INCOMING ${protocol.toUpperCase()} DATA FROM CLIENT:
---BEGIN CLIENT INPUT---
${safeInput}
---END CLIENT INPUT---
Generate the simulated protocol response (raw output only):`;

    if (context.fileContents) {
        userPrompt += `\n\n[FILE_SYSTEM]\n${context.fileContents}`;
    }

    try {
        let response;
        if (ai.provider === 'ollama') {
            const numPredict = ['http', 'ssh', 'telnet'].includes(protocol) ? 512 : 128;
            response = await queryOllama(systemPrompt, userPrompt, numPredict);
        } else {
            response = await queryOpenAI(systemPrompt, userPrompt);
        }

        // 5. Validate output — ensure it doesn't accidentally contain real-looking secrets
        response = sanitizeOutput(response, protocol);

        // 6. HIGH-01 + MED-04: Validate output doesn't leak honeypot identity
        response = validateOutputIdentity(response, protocol);

        return response;
    } catch (err) {
        logger.warn(`AI generation failed (${protocol}): ${err.message}`, { protocol });
        return getFallback(protocol);
    }
}

async function queryOllama(system, prompt, numPredict = 512) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), ai.timeout || 60000);

    try {
        const res = await axios.post(`${ai.url}/api/generate`, {
            model:   ai.model,
            system,
            prompt,
            stream:  false,
            keep_alive: ai.keep_alive !== undefined ? ai.keep_alive : "10s",
            options: { temperature: ai.temperature || 0.9, num_predict: numPredict }
        }, { 
            signal: controller.signal
        });
        clearTimeout(timeoutId);

        let text = String(res.data.response || '');

        // Strip <think>...</think> chain-of-thought (qwen3, deepseek-r1)
        text = text.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
        // Strip markdown fences
        text = text.replace(/^```[\w]*\n?/gm, '').replace(/\n?```$/gm, '').trim();

        // Strip AI meta-markers that leak honeypot nature
        text = text.replace(/---\s*(END|BEGIN)\s*(DECEPTIVE|FAKE|HONEYPOT)\s*RESPONSE\s*---/gi, '').trim();
        text = text.replace(/\[Note:.*?\]/gi, '').trim();
        text = text.replace(/\(This is a (fake|deceptive|honeypot).*?\)/gi, '').trim();
        text = text.replace(/^(Here is|Here's|Below is).*?:$/gim, '').trim();

        return text.substring(0, MAX_OUTPUT_BYTES);
    } catch (err) {
        clearTimeout(timeoutId);
        throw err;
    }
}

async function queryOpenAI(system, prompt) {
    const res = await axios.post(`${ai.url}/v1/chat/completions`, {
        model:       ai.model,
        messages:    [
            { role: 'system', content: system },
            { role: 'user',   content: prompt }
        ],
        temperature: ai.temperature || 0.9,
        max_tokens:  512
    }, {
        headers: { Authorization: `Bearer ${process.env.OPENAI_KEY || 'dummy'}` },
        timeout: ai.timeout || 60000
    });

    return String(res.data.choices?.[0]?.message?.content || '').trim()
        .substring(0, MAX_OUTPUT_BYTES);
}

// ─── Output sanitization ──────────────────────────────────────────────────────
// Prevent the AI from accidentally leaking real-looking sensitive patterns
// These patterns would be real if the AI hallucinates real-format keys
const REAL_SECRET_PATTERNS = [
    // Real-format AWS keys (AKIA...)
    /AKIA[0-9A-Z]{16}/g,
    // Real private key headers (we want FAKE ones so just strip real PEM headers)
    /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    // Real-looking API key patterns that are 32+ hex chars with specific prefixes
    /sk-[a-zA-Z0-9]{48,}/g,
    // Internal IP leakage (real infrastructure IPs from common private ranges)
    /192\.168\.1\.\d{1,3}/g,
    // Tailscale internal IP
    /100\.71\.140\.\d{1,3}/g,
    // Ollama API endpoint leak
    /http:\/\/192\.168\./g,
    /localhost:11434/g,
];

function sanitizeOutput(text, protocol) {
    let clean = text;
    REAL_SECRET_PATTERNS.forEach(pattern => {
        clean = clean.replace(pattern, '[REDACTED]');
    });
    return clean;
}

// ── HIGH-01 + MED-04: Output identity leak detection ─────────────────────
// Detect when the LLM accidentally reveals it's a honeypot/AI/simulation
const IDENTITY_LEAK_PATTERNS = [
    /you are a (linux|web|ftp|smtp|redis|mysql)/i,   // System prompt echo
    /honey[\s-]?pot/i,                                // Direct identity leak (matches honeypot, honey pot, honey-pot)
    /h[0o]n[3e]y[\s-]?p[0o]t/i,                      // Leetspeak direct identity leak
    /decoy|señuelo|cebo|leurre|köder|esca|chamariz|приманка|蜜罐/i, // Block decoy leaks (multilingual: EN, ES, FR, DE, IT, PT, RU, ZH)
    /trap\b|trampa|piège|falle|trappola|armadilha|ловушка/i, // Block trap leaks (multilingual)
    /honeyai|openclaw|honey[\s-]?ai/i,                // Product name leak
    /i('m| am) an? (ai|language model|llm|chatbot)/i, // AI identity reveal
    /soy un(a)? (ia|inteligencia artificial|modelo de lenguaje|chatbot)/i,
    /je suis une? (ia|intelligence artificielle|modèle de langage|chatbot)/i,
    /ich bin ein(e)? (ki|künstliche intelligenz|sprachmodell|chatbot)/i,
    /sono (un'?|una? )?(ia|intelligenza artificiale|modello linguistico|chatbot)/i,
    /sou (um |uma )?(ia|intelig[eê]ncia artificial|modelo de linguagem|chatbot)/i,
    /system prompt/i,                                  // Meta prompt leak
    /prompt del sistema|instrucciones del sistema|consigne du système/i,
    /ATTACKER_PAYLOAD/i,                               // Our injection wrapper leaked
    /simul(ad[aoe]s?r?|aci[oó]n|azi[oó]ne|ar|at(e|ing|ion|ed?|o|i|a|s|es?))\b/i, // "simulated response" (multilingual)
    /this is (a |)(fake|deceptive|not real)/i,         // Self-identification
    /esto es (falso|una simulación|de mentira|un simulacro)/i,
    /ceci est (un fake|faux|une simulation)/i,
    /questo è un server (finto|falso|simulato|non reale|non vero)|non sono un (vero|reale) server/i,
    /isto é um servidor (falso|simulado|não real|não verdadeiro)|não sou um servidor (real|verdadeiro)|não é um servidor real/i,
    /as an ai/i,                                       // Common AI disclosure
    /como una? (ia|inteligencia artificial)/i,
    /en tant que (ia|intelligence artificielle)/i,
    /i cannot (actually|really)/i,                     // AI limitation reveal
    /no puedo (realmente|de verdad)/i,
    /---\s*(BEGIN|END)\s*CLIENT\s*INPUT\s*---/i,       // Our prompt template leaked
];

function validateOutputIdentity(text, protocol) {
    for (const pattern of IDENTITY_LEAK_PATTERNS) {
        if (pattern.test(text)) {
            logger.warn(`LLM response leaked honeypot identity (${protocol}) — matched: ${pattern} — Content: "${text}"`, { protocol });
            return getFallback(protocol);
        }
    }
    return text;
}

// ─── Static fallbacks when AI is unavailable ──────────────────────────────────
const FALLBACKS = {
    http:    `<html><body><h1>500 Internal Server Error</h1><p>The server encountered an internal error and was unable to complete your request.</p></body></html>`,
    ssh:     `bash: command not found`,
    ftp:     `425 Can't open data connection.`,
    telnet:  `Connection to host lost.`,
    smtp:    `250 2.0.0 Ok: queued as A1B2C3D4`,
    mysql:   `ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)`,
    redis:   `-ERR NOAUTH Authentication required`,
    default: `Connection reset by peer.`
};

function getFallback(protocol) {
    return FALLBACKS[protocol] || FALLBACKS.default;
}

// ─── Telnet / Cisco Command Static Interception ──────────────────────────────────
const STATIC_TELNET_COMMANDS = Object.assign(Object.create(null), {
    'show running-config': `Building configuration...

Current configuration : 1042 bytes
!
version 12.4
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname Router
!
boot-start-marker
boot-end-marker
!
no aaa new-model
!
resource policy
!
interface FastEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 duplex auto
 speed auto
!
interface FastEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 duplex auto
 speed auto
!
router rip
 network 192.168.1.0
 network 10.0.0.0
!
ip http server
no ip http secure-server
!
control-plane
!
line con 0
line aux 0
line vty 0 4
 login
!
end`,
    'show run': `Building configuration...

Current configuration : 1042 bytes
!
version 12.4
!
hostname Router
!
interface FastEthernet0/0
 ip address 192.168.1.1 255.255.255.0
!
interface FastEthernet0/1
 ip address 10.0.0.1 255.255.255.0
!
router rip
 network 192.168.1.0
!
end`,
    'show ip route': `Codes: C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area 
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2
       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2
       ia - IS-IS inter area, * - candidate default, U - per-user static route
       o - ODR, P - periodic downloaded static route

Gateway of last resort is not set

      10.0.0.0/24 is subnetted, 1 subnets
C        10.0.0.0 is directly connected, FastEthernet0/1
      192.168.1.0/24 is subnetted, 1 subnets
C        192.168.1.0 is directly connected, FastEthernet0/0`,
    'show interfaces': `FastEthernet0/0 is up, line protocol is up 
  Hardware is GigaEthernet, address is 000c.29ff.38a1 (bia 000c.29ff.38a1)
  Internet address is 192.168.1.1/24
  MTU 1500 bytes, BW 100000 Kbit, DLY 100 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Full-duplex, 100Mb/s, media type is RJ45
  Output flow-control is unsupported, input flow-control is unsupported
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:01, output 00:00:00, output hang never
  Last clearing of "show interface" counters never`,
    'enable': 'Password: \r\nRouter#',
    'exit': 'Connection closed by foreign host.'
});

function getStaticTelnetResponse(cmd) {
    const cleanCmd = cmd.trim().toLowerCase();
    if (STATIC_TELNET_COMMANDS[cleanCmd] !== undefined) {
        return STATIC_TELNET_COMMANDS[cleanCmd];
    }
    return null;
}

module.exports = { generate, validateOutputIdentity };
