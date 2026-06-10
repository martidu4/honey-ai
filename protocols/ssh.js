/**
 * OpenClaw HoneyAI — SSH Honeypot
 * Replaces Cowrie. Fake interactive SSH shell + optional tarpit ports.
 * Uses the `ssh2` library to handle the SSH handshake properly.
 */

const net    = require('net');
const ssh2   = require('ssh2');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const config = require('../core/config');
const { logger, logEvent, sanitizeForLog } = require('../core/logger');
const reporter = require('../core/reporter');
const ai       = require('../ai/engine');
const downloader = require('../core/downloader');
const { sleep, writeWithJitter } = require('../core/jitter');

// ─── Canary Tokens / honeyfs Integration ──────────────────────────────────────
const HONEYFS_DIR = path.join(__dirname, '../honeyfs');
const canaryMap = new Map();

function loadHoneyFS(dir, baseDir = dir) {
    if (!fs.existsSync(dir)) return;
    try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                loadHoneyFS(fullPath, baseDir);
            } else {
                const relPath = '/' + path.relative(baseDir, fullPath);
                const fileName = entry.name;
                canaryMap.set(relPath.toLowerCase(), fullPath);
                canaryMap.set(fileName.toLowerCase(), fullPath);
            }
        }
    } catch (err) {
        logger.error(`Error loading honeyfs directory: ${err.message}`, { protocol: 'ssh' });
    }
}

function getCanaryResponse(command) {
    if (!command) return null;
    
    // Match common read commands: cat, less, more, head, tail, strings
    const match = command.match(/^\s*(cat|less|more|head|tail|strings)\s+(.+)$/i);
    if (!match) return null;
    
    let filePath = match[2].trim();
    // Strip quotes and redirection signs if any
    filePath = filePath.replace(/['"]/g, '').split(/\s/)[0];
    filePath = filePath.replace(/^~/, '/root'); // Expand home directory for root
    filePath = filePath.replace(/^\.\//, ''); // strip ./
    
    // ── PATH TRAVERSAL DEFENSE (CRIT-02) ──────────────────────────────────
    // Block any path containing ../ which is the classic traversal attack
    if (filePath.includes('..')) {
        logger.warn(`Path traversal attempt blocked: ${sanitizeForLog(filePath)}`, { protocol: 'ssh' });
        return null; // Fall through to AI — attacker sees nothing suspicious
    }
    
    const key = filePath.toLowerCase();
    const keyWithSlash = filePath.startsWith('/') ? key : '/' + key;
    
    // Lookup in canaryMap — tries exact path, then /prefixed, then basename
    let realPath = canaryMap.get(key) || canaryMap.get(keyWithSlash);
    if (!realPath) {
        const baseName = path.basename(filePath).toLowerCase();
        realPath = canaryMap.get(baseName);
    }
    
    // Double-check: the matched canary file MUST physically be inside honeyfs
    // This is the real guard — even if canaryMap is somehow poisoned, we never
    // read outside the honeyfs directory
    if (realPath) {
        const resolvedCanary = path.resolve(realPath);
        if (!resolvedCanary.startsWith(path.resolve(HONEYFS_DIR))) {
            logger.warn(`Canary path escape blocked: ${realPath}`, { protocol: 'ssh' });
            return null;
        }
    }
    
    if (realPath && fs.existsSync(realPath)) {
        try {
            return fs.readFileSync(realPath, 'utf8');
        } catch (err) {
            logger.error(`Error reading canary token file ${realPath}: ${err.message}`, { protocol: 'ssh' });
        }
    }
    return null;
}

function getReferencedFiles(command) {
    if (!command) return '';
    const lowerCmd = command.toLowerCase();
    const matchedPaths = new Set();
    let refs = '';
    
    for (const [key, filePath] of canaryMap.entries()) {
        const escapedKey = key.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
        const regex = new RegExp(`\\b${escapedKey}\\b`, 'i');
        
        if (regex.test(lowerCmd)) {
            matchedPaths.add(filePath);
        }
    }

    for (const filePath of matchedPaths) {
        try {
            if (fs.existsSync(filePath)) {
                const content = fs.readFileSync(filePath, 'utf8');
                const relativeName = path.basename(filePath);
                refs += `${relativeName} containing:\n${content}\n\n`;
            }
        } catch (_) {}
    }
    return refs;
}

// ── Persistent host key (LOW-01) — same fingerprint across restarts ────────
const HOST_KEY_PATH = path.join(__dirname, '../.host_key');
let HOST_KEY;
try {
    if (fs.existsSync(HOST_KEY_PATH)) {
        HOST_KEY = { privateKey: fs.readFileSync(HOST_KEY_PATH, 'utf8') };
    } else {
        HOST_KEY = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding:  { type: 'spki',  format: 'pem' },
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
        });
        fs.writeFileSync(HOST_KEY_PATH, HOST_KEY.privateKey, { mode: 0o600 });
        logger.info('Generated and saved persistent SSH host key', { protocol: 'ssh' });
    }
} catch (err) {
    // Fallback: ephemeral key if disk write fails (e.g. read-only fs)
    HOST_KEY = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding:  { type: 'spki',  format: 'pem' },
        privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
    });
}

function start(customCfg) {
    const cfg = customCfg || config.protocols.ssh;
    if (!cfg?.enabled) return null;

    // Load honeyfs for Canary Tokens
    loadHoneyFS(HONEYFS_DIR);

    // ── Main interactive SSH honeypot ──────────────────────────────────────
    const sshServer = startInteractiveSSH(cfg);

    const tarpitServers = [];
    // ── Tarpit ports (endless banner, replaces Endlessh) ──────────────────
    if (cfg.tarpit && cfg.tarpit_ports?.length) {
        cfg.tarpit_ports.forEach(port => {
            const tarpitSrv = startTarpit(port);
            if (tarpitSrv) tarpitServers.push(tarpitSrv);
        });
    }

    return { sshServer, tarpitServers };
}

const SSH_CONNECTION_COUNTS = new Map();
const MAX_SSH_CONN_PER_MINUTE = 15;

setInterval(() => SSH_CONNECTION_COUNTS.clear(), 60_000);

function getSSHRateLimitStatus(ip) {
    const slot = SSH_CONNECTION_COUNTS.get(ip) || { count: 0 };
    slot.count++;
    SSH_CONNECTION_COUNTS.set(ip, slot);

    if (slot.count === MAX_SSH_CONN_PER_MINUTE + 1) {
        return 1; // First block
    }
    if (slot.count > MAX_SSH_CONN_PER_MINUTE) {
        return 2; // Silent block
    }
    return 0; // Allowed
}

function startInteractiveSSH(cfg) {
    const srv = new ssh2.Server({
        hostKeys: [HOST_KEY.privateKey],
        ident:    cfg.ident || 'OpenSSH_9.2p1 Debian-2+deb12u3',
        banner:   cfg.banner || 'Debian GNU/Linux 12'  // LOW-03: match ident string
    }, (client) => {
        const ip = (client._sock?.remoteAddress || 'unknown').replace(/^::ffff:/, '');

        const limitStatus = getSSHRateLimitStatus(ip);
        if (limitStatus > 0) {
            if (limitStatus === 1) {
                logger.warn(`SSH connection rate limit hit for ${ip} (further connections silenced)`, { protocol: 'ssh', ip });
            }
            if (client._sock && typeof client._sock.destroy === 'function') {
                client._sock.destroy();
            } else {
                client.destroy();
            }
            return;
        }

        logger.info(`New connection`, { protocol: 'ssh', ip });

        if (global.activeConnections && global.activeConnections.ssh !== undefined) {
            global.activeConnections.ssh++;
        }
        let decremented = false;
        const decrement = () => {
            if (!decremented) {
                decremented = true;
                if (global.activeConnections && global.activeConnections.ssh !== undefined) {
                    global.activeConnections.ssh--;
                }
            }
        };
        client.on('close', decrement);
        client.on('end', decrement);
        client.on('error', decrement);

        client.on('authentication', (ctx) => {
            const username = ctx.username;
            // MED-05: Redact passwords in console logs (full value kept in events.json for intel)
            const safePass = ctx.method === 'password'
                ? (ctx.password?.substring(0, 2) || '') + '***'
                : '(key)';

            logger.info(`Auth attempt user="${sanitizeForLog(username)}" pass="${sanitizeForLog(safePass)}"`, { protocol: 'ssh', ip });

            logEvent({
                protocol:  'ssh',
                ip,
                username,
                password_hash: ctx.method === 'password'
                    ? require('crypto').createHash('sha256').update(ctx.password || '').digest('hex').substring(0, 16)
                    : null,
                password_length: ctx.method === 'password' ? (ctx.password?.length || 0) : null,
                auth_method: ctx.method
            });

            // Accept ALL credentials — we want them in!
            // MED-02: Artificial delay to throttle brute-force bots and prevent
            // event/report flooding (2-3s random delay simulates real auth latency)
            setTimeout(() => ctx.accept(), 2000 + Math.random() * 1000);
        });

        client.on('ready', () => {
            logger.info(`Login accepted — shell session starting`, { protocol: 'ssh', ip });

            // Pre-seed per-client session state
            const sessionState = {
                cwd: '/root',
                virtualFS: new Map()
            };
            for (const [key, filePath] of canaryMap.entries()) {
                let relPath = key.startsWith('/') ? key : '/' + key;
                try {
                    if (fs.existsSync(filePath)) {
                        sessionState.virtualFS.set(relPath, fs.readFileSync(filePath, 'utf8'));
                    }
                } catch (_) {}
            }

            reporter.report(ip, {
                protocol: 'ssh',
                port: cfg.port || 2222,
                comment: `SSH brute-force login to honeypot. OpenClaw HoneyAI.`,
                categories: '22,18'
            }).catch(() => {});

            client.on('session', (accept) => {
                const session = accept();

                session.on('shell', (accept) => {
                    const stream = accept();
                    runFakeShell(stream, ip, cfg, sessionState);
                });

                session.on('exec', (accept, reject, info) => {
                    const stream = accept();
                    handleExecCommand(stream, info.command, ip, cfg, sessionState);
                });

                session.on('pty', (accept) => accept?.());
                session.on('env',  (accept) => accept?.());
            });
        });

        client.on('error', () => {});
        client.on('end',   () => logger.info(`Session ended`, { protocol: 'ssh', ip }));
    });

    srv.maxConnections = 500;

    const port = cfg.port || 2222;
    srv.listen(port, '0.0.0.0', () => {
        logger.info(`SSH honeypot listening on :${port}`, { protocol: 'ssh' });
    });

    srv.on('error', (err) => logger.error(`SSH server error: ${err.message}`, { protocol: 'ssh' }));
    return srv;
}

const STATIC_SSH_COMMANDS = Object.assign(Object.create(null), {
    'whoami': 'root',
    'id': 'uid=0(root) gid=0(root) groups=0(root)',
    'uname': 'Linux',
    'uname -a': 'Linux prod-server-01 6.1.0-9-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.27-1 (2023-05-08) x86_64 GNU/Linux',
    'hostname': 'prod-server-01',
    'df': 'Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1       41251136 8931204  32319932  22% /',
    'df -h': 'Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G  8.6G   31G  22% /',
    'free': '               total        used        free      shared  buff/cache   available\nMem:         8123048     2138944     4128912      102432     1855192     5692016\nSwap:        2097148           0     2097148',
    'free -m': '               total        used        free      shared  buff/cache   available\nMem:            7932        2039        3937          97        1769        5428\nSwap:           2047           0        2047',
    'free -h': '               total        used        free      shared  buff/cache   available\nMem:           7.7Gi       2.0Gi       3.8Gi        97Mi       1.7Gi       5.3Gi\nSwap:          2.0Gi        0.B        2.0Gi',
    'w': ' 08:45:12 up 14 days,  3:12,  1 user,  load average: 0.00, 0.01, 0.05\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    10.0.0.2         08:40    1.00s  0.02s  0.00s w',
    'who': 'root     pts/0        2026-06-09 08:40 (10.0.0.2)',
    'uptime': ' 08:45:15 up 14 days,  3:12,  1 user,  load average: 0.00, 0.01, 0.05',
    'pwd': (state) => state.cwd,
    'cat /proc/cpuinfo': 'processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 142\nmodel name\t: Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz\nstepping\t: 11\ncpu MHz\t\t: 1800.000\ncache size\t: 6144 KB\nphysical id\t: 0\nsiblings\t: 4\ncore id\t\t: 0\ncpu cores\t: 4\napicid\t\t: 0\ninitial apicid\t: 0\nfpu\t\t: yes\nfpu_exception\t: yes\ncpuid level\t: 22\nwp\t\t: yes\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt intel_pt sgx xsaveopt xsavec xgetbv1 xsaves dtherm\nbugs\t\t: spectre_v1 spectre_v2 spec_store_bypass mds swapgs taa itlb_multihit srbds mmio_stale_data retbleed gds\nbogomips\t: 3600.00\nclflush size\t: 64\ncache_alignment\t: 64\naddress sizes\t: 39 bits physical, 48 bits virtual\npower management:\n',
    'cat /proc/self/cgroup': '12:pids:/docker/c1e3a5f78b90a6e8f812d34e9100fa1b\n11:devices:/docker/c1e3a5f78b90a6e8f812d34e9100fa1b\n10:memory:/docker/c1e3a5f78b90a6e8f812d34e9100fa1b\n9:cpu,cpuacct:/docker/c1e3a5f78b90a6e8f812d34e9100fa1b\n8:cpuset:/docker/c1e3a5f78b90a6e8f812d34e9100fa1b\n7:net_cls,net_prio:/docker/c1e3a5f78b90a6e8f812d34e9100fa1b\n6:blkio:/docker/c1e3a5f78b90a6e8f812d34e9100fa1b\n5:perf_event:/docker/c1e3a5f78b90a6e8f812d34e9100fa1b\n4:hugetlb:/docker/c1e3a5f78b90a6e8f812d34e9100fa1b\n3:freezer:/docker/c1e3a5f78b90a6e8f812d34e9100fa1b\n2:rdma:/docker/c1e3a5f78b90a6e8f812d34e9100fa1b\n1:name=systemd:/docker/c1e3a5f78b90a6e8f812d34e9100fa1b',
    'docker ps': 'CONTAINER ID   IMAGE          COMMAND                  CREATED         STATUS         PORTS                               NAMES\nc1e3a5f78b90   nginx:alpine   "/docker-entrypoint.…"   2 hours ago     Up 2 hours     0.0.0.0:80->80/tcp, :::80->80/tcp   web-nginx\n3a9f82d104be   redis:latest   "docker-entrypoint.s…"   2 hours ago     Up 2 hours     0.0.0.0:6379->6379/tcp              redis-cache\n9f82b71a39d8   mysql:8.0      "docker-entrypoint.s…"   24 hours ago    Up 24 hours    3306/tcp                            mysql-db',
    'docker ps -a': 'CONTAINER ID   IMAGE          COMMAND                  CREATED         STATUS         PORTS                               NAMES\nc1e3a5f78b90   nginx:alpine   "/docker-entrypoint.…"   2 hours ago     Up 2 hours     0.0.0.0:80->80/tcp, :::80->80/tcp   web-nginx\n3a9f82d104be   redis:latest   "docker-entrypoint.s…"   2 hours ago     Up 2 hours     0.0.0.0:6379->6379/tcp              redis-cache\n9f82b71a39d8   mysql:8.0      "docker-entrypoint.s…"   24 hours ago    Up 24 hours    3306/tcp                            mysql-db',
    'docker images': 'REPOSITORY   TAG       IMAGE ID       CREATED        SIZE\nnginx        alpine    51a23b9d10e8   2 days ago     23.5MB\nredis        latest    8f3b92d04ca1   5 days ago     113MB\nmysql        8.0       3a12b9d82cb4   2 weeks ago    445MB',
    'kubectl get pods': 'NAME                            READY   STATUS    RESTARTS   AGE\napi-gateway-7f8b9-x2b4a         1/1     Running   0          5d12h\nauth-service-d48e2-9k8f7        1/1     Running   0          5d12h\nuser-db-0                       1/1     Running   0          24d\nredis-session-cache-7d8a-9f82   1/1     Running   1          2d4h',
    'kubectl get pods -A': 'NAMESPACE     NAME                            READY   STATUS    RESTARTS   AGE\ndefault       api-gateway-7f8b9-x2b4a         1/1     Running   0          5d12h\ndefault       auth-service-d48e2-9k8f7        1/1     Running   0          5d12h\ndefault       user-db-0                       1/1     Running   0          24d\ndefault       redis-session-cache-7d8a-9f82   1/1     Running   1          2d4h\nkube-system   coredns-5c6b6c5476-8f72a        1/1     Running   0          25d\nkube-system   kube-proxy-8x9d2                1/1     Running   0          25d',
    'kubectl get nodes': 'NAME           STATUS   ROLES    AGE   VERSION\nk8s-master-1   Ready    control-plane   25d   v1.28.2\nk8s-node-01    Ready    worker          25d   v1.28.2\nk8s-node-02    Ready    worker          25d   v1.28.2',
    'kubectl cluster-info': 'Kubernetes control plane is running at https://192.168.1.150:6443\nCoreDNS is running at https://192.168.1.150:6443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy\n\nTo further debug and diagnose cluster problems, use \'kubectl cluster-info dump\'.'
});

function getStaticSSHResponse(cmd, sessionState) {
    const cleanCmd = cmd.trim();
    if (STATIC_SSH_COMMANDS[cleanCmd] !== undefined) {
        const val = STATIC_SSH_COMMANDS[cleanCmd];
        return typeof val === 'function' ? val(sessionState) : val;
    }
    const tokens = cleanCmd.split(/\s+/);
    if (tokens[0] === 'cd') {
        return '';
    }
    return null;
}

// ─── Fake interactive shell ────────────────────────────────────────────────────
function resolvePath(currentCwd, targetPath) {
    if (!targetPath) return currentCwd;
    let resolved = targetPath.startsWith('/')
        ? path.normalize(targetPath)
        : path.normalize(path.join(currentCwd, targetPath));
    resolved = resolved.replace(/\\/g, '/');
    if (!resolved.startsWith('/')) resolved = '/' + resolved;
    if (resolved.length > 1 && resolved.endsWith('/')) {
        resolved = resolved.slice(0, -1);
    }
    return resolved;
}

function parseFSCommand(cmd, sessionState) {
    const tokens = cmd.split(/\s+/);
    const primary = tokens[0]?.toLowerCase();

    if (primary === 'cd') {
        const target = tokens[1] || '~';
        if (target === '~') {
            sessionState.cwd = '/root';
        } else {
            sessionState.cwd = resolvePath(sessionState.cwd, target);
        }
        return true;
    }

    if (primary === 'mkdir') {
        const target = tokens[1];
        if (target) {
            const folderPath = resolvePath(sessionState.cwd, target);
            sessionState.virtualFS.set(folderPath, null);
        }
        return true;
    }

    if (primary === 'touch') {
        const target = tokens[1];
        if (target) {
            const filePath = resolvePath(sessionState.cwd, target);
            if (!sessionState.virtualFS.has(filePath)) {
                sessionState.virtualFS.set(filePath, '');
            }
        }
        return true;
    }

    if (primary === 'rm') {
        const target = tokens.find(t => t && !t.startsWith('-') && t !== 'rm');
        if (target) {
            const filePath = resolvePath(sessionState.cwd, target);
            sessionState.virtualFS.delete(filePath);
            for (const key of sessionState.virtualFS.keys()) {
                if (key.startsWith(filePath + '/')) {
                    sessionState.virtualFS.delete(key);
                }
            }
        }
        return true;
    }

    if (primary === 'echo') {
        const matchRedirect = cmd.match(/(.+?)\s*(>>|>)\s*(.+)/);
        if (matchRedirect) {
            let content = matchRedirect[1].trim();
            if (content.toLowerCase().startsWith('echo')) {
                content = content.substring(4).trim();
            }
            content = content.replace(/^['"]|['"]$/g, '');
            const operator = matchRedirect[2];
            const targetFile = matchRedirect[3].trim().replace(/^['"]|['"]$/g, '');

            const filePath = resolvePath(sessionState.cwd, targetFile);
            if (operator === '>') {
                sessionState.virtualFS.set(filePath, content);
            } else {
                const existing = sessionState.virtualFS.get(filePath) || '';
                sessionState.virtualFS.set(filePath, existing + '\n' + content);
            }
            return true;
        }
    }

    return false;
}

function getFSContext(cmd, sessionState) {
    let contextStr = `Current Working Directory: ${sessionState.cwd}\n\n`;
    contextStr += `Files in current directory:\n`;
    const filesInCwd = [];
    for (const [filePath, content] of sessionState.virtualFS.entries()) {
        const parentDir = path.dirname(filePath);
        if (parentDir === sessionState.cwd) {
            const name = path.basename(filePath);
            filesInCwd.push(name + (content === null ? '/' : ''));
        }
    }
    contextStr += filesInCwd.join(', ') + '\n\n';

    const lowerCmd = cmd.toLowerCase();
    let fileDetails = '';
    for (const [filePath, content] of sessionState.virtualFS.entries()) {
        const name = path.basename(filePath);
        if (lowerCmd.includes(name.toLowerCase()) && content !== null) {
            fileDetails += `File ${name} contents:\n${content}\n\n`;
        }
    }
    if (fileDetails) {
        contextStr += `Referenced files contents:\n${fileDetails}`;
    }

    return contextStr;
}

async function handleDownloadCommand(cmd, ip) {
    const urls = downloader.extractURLs(cmd);
    if (urls.length === 0) return null;

    const url = urls[0];
    const result = await downloader.processDownload(url, ip, 'ssh');
    if (result) {
        return downloader.getFakeCLIOutput(url, result.filename, result.size);
    }
    return null;
}

async function writeSSHOutput(stream, text) {
    if (!text) return;
    const formatted = text.replace(/\n/g, '\r\n');
    
    // Simulate connection processing delay (jitter)
    await sleep(150, 400);

    if (formatted.length < 200) {
        // Character by character typing for short text
        await writeWithJitter(stream, formatted + '\r\n', 5, 15);
    } else {
        // Write line by line with minor delay for long outputs
        const lines = (formatted + '\r\n').split('\r\n');
        for (let i = 0; i < lines.length - 1; i++) {
            if (stream.destroyed || stream.writableEnded) break;
            stream.write(lines[i] + '\r\n');
            await sleep(10, 30);
        }
    }
}

async function runFakeShell(stream, ip, cfg, sessionState) {
    const hostname = cfg.fake_hostname || 'prod-server-01';
    stream.write(`Debian GNU/Linux 12 (bookworm)\r\n\r\n`);
    stream.write(`Last login: ${new Date(Date.now() - 86400000).toUTCString()} from 10.0.0.2\r\n`);
    
    const printPrompt = () => {
        const displayCwd = sessionState.cwd === '/root' ? '~' : sessionState.cwd;
        stream.write(`root@${hostname}:${displayCwd}# `);
    };

    printPrompt();

    let buffer = '';
    let activeTarpit = null;

    stream.on('data', async (data) => {
        const chunk = data.toString();

        for (let i = 0; i < chunk.length; i++) {
            const char = chunk[i];

            if (char === '\x03') { // Ctrl+C
                if (activeTarpit) {
                    activeTarpit();
                    activeTarpit = null;
                }
                stream.write('^C\r\n');
                buffer = '';
                printPrompt();
                continue;
            }

            if (activeTarpit) {
                // Ignore other keypresses while tarpit is active
                continue;
            }

            if (char === '\x7f' || char === '\b') {
                if (buffer.length > 0) {
                    buffer = buffer.slice(0, -1);
                    stream.write('\b \b');
                }
                continue;
            }

            stream.write(char);

            if (char === '\r' || char === '\n') {
                const cmd = buffer.trim();
                buffer = '';
                stream.write('\r\n');

                if (cmd === 'exit' || cmd === 'logout') {
                    stream.write('logout\r\n');
                    stream.end();
                    return;
                }

                if (cmd) {
                    logEvent({ protocol: 'ssh', ip, command: cmd });

                    // 1. Intercept download
                    const downloadResult = await handleDownloadCommand(cmd, ip);
                    if (downloadResult) {
                        await writeSSHOutput(stream, downloadResult);
                        try {
                            const urls = downloader.extractURLs(cmd);
                            const url = new URL(urls[0]);
                            const filename = path.basename(url.pathname) || 'downloaded_file';
                            const filePath = resolvePath(sessionState.cwd, filename);
                            sessionState.virtualFS.set(filePath, '#!/bin/bash\n# Simulated payload\n');
                        } catch (_) {}
                        printPrompt();
                        continue;
                    }

                    // 2. Parse Virtual FS changes
                    parseFSCommand(cmd, sessionState);

                    // 2b. Intercept GZIP/ZIP bomb file reads
                    const readMatch = cmd.match(/^\s*(cat|less|more|head|tail|strings)\s+(.+)$/i);
                    let isBomb = false;
                    if (readMatch) {
                        let filePath = readMatch[2].trim().replace(/['"]/g, '').split(/\s/)[0];
                        const lowerPath = filePath.toLowerCase();
                        if (lowerPath.endsWith('.zip') || lowerPath.endsWith('.gz') || lowerPath.endsWith('.tar.gz') || lowerPath.endsWith('.sql.gz')) {
                            isBomb = true;
                        }
                    }

                    if (isBomb) {
                        logger.warn(`SSH GZIP bomb triggered: ${sanitizeForLog(cmd)}`, { protocol: 'ssh', ip });
                        logEvent({ protocol: 'ssh', ip, command: cmd, attack_type: 'ssh_gzip_bomb_triggered' });
                        reporter.report(ip, {
                            protocol: 'ssh',
                            port: cfg.port || 2222,
                            comment: `SSH backup read attempt -> GZIP bomb triggered: ${cmd}`,
                            categories: '22,18'
                        }).catch(() => {});

                        const chunk = crypto.randomBytes(65536);
                        for (let c = 0; c < 150; c++) {
                            if (stream.destroyed || stream.writableEnded) break;
                            stream.write(chunk);
                            await sleep(5, 15);
                        }
                        stream.write('\r\n');
                        printPrompt();
                        continue;
                    }

                    // 2c. Intercept SSH Command Tarpit
                    const lowerCmd = cmd.toLowerCase().trim();
                    const isTarpitCmd = lowerCmd.startsWith('ping') || lowerCmd.startsWith('find') || lowerCmd.startsWith('grep') || lowerCmd.startsWith('nmap') || lowerCmd.startsWith('masscan');
                    if (isTarpitCmd) {
                        logger.warn(`SSH command tarpit triggered: ${sanitizeForLog(cmd)}`, { protocol: 'ssh', ip });
                        logEvent({ protocol: 'ssh', ip, command: cmd, attack_type: 'ssh_command_tarpit_triggered' });
                        reporter.report(ip, {
                            protocol: 'ssh',
                            port: cfg.port || 2222,
                            comment: `SSH command tarpit triggered for command: "${cmd}"`,
                            categories: '22,18'
                        }).catch(() => {});

                        const traps = require('../core/traps');
                        activeTarpit = traps.tarpitSSHCommand(stream, cmd, () => {
                            activeTarpit = null;
                            printPrompt();
                        });
                        continue;
                    }

                    // 3. Fallback, Canary or Static response, or LLM Generation
                    const canaryResponse = getCanaryResponse(cmd);
                    const staticResponse = getStaticSSHResponse(cmd, sessionState);
                    if (canaryResponse !== null) {
                        await writeSSHOutput(stream, canaryResponse);
                    } else if (staticResponse !== null) {
                        if (staticResponse.length > 0) {
                            await writeSSHOutput(stream, staticResponse);
                        }
                    } else {
                        const fsContext = getFSContext(cmd, sessionState);
                        const response = await ai.generate({
                            protocol: 'ssh',
                            attackerInput: `Command: ${cmd}`,
                            context: { ip, hostname, port: cfg.port, fileContents: fsContext }
                        });

                        await writeSSHOutput(stream, response);
                    }
                }

                printPrompt();
            } else {
                buffer += char;
                if (buffer.length > 4096) {
                    stream.write('\r\nCommand too long.\r\n');
                    buffer = '';
                    printPrompt();
                }
            }
        }
    });

    stream.on('error', () => {});
    stream.on('close', () => {});
}

// ─── Handle non-interactive exec commands ─────────────────────────────────────
async function handleExecCommand(stream, command, ip, cfg, sessionState) {
    command = (command || '').substring(0, 4096);
    logEvent({ protocol: 'ssh', ip, command, mode: 'exec' });

    // 1. Intercept download
    const downloadResult = await handleDownloadCommand(command, ip);
    if (downloadResult) {
        await writeSSHOutput(stream, downloadResult);
        stream.exit(0);
        stream.end();
        return;
    }

    // 2. Parse Virtual FS changes
    parseFSCommand(command, sessionState);

    // 2b. Intercept GZIP/ZIP bomb file reads
    const readMatchExec = command.match(/^\s*(cat|less|more|head|tail|strings)\s+(.+)$/i);
    let isBombExec = false;
    if (readMatchExec) {
        let filePath = readMatchExec[2].trim().replace(/['"]/g, '').split(/\s/)[0];
        const lowerPath = filePath.toLowerCase();
        if (lowerPath.endsWith('.zip') || lowerPath.endsWith('.gz') || lowerPath.endsWith('.tar.gz') || lowerPath.endsWith('.sql.gz')) {
            isBombExec = true;
        }
    }

    if (isBombExec) {
        logger.warn(`SSH exec GZIP bomb triggered: ${sanitizeForLog(command)}`, { protocol: 'ssh', ip });
        logEvent({ protocol: 'ssh', ip, command, mode: 'exec', attack_type: 'ssh_gzip_bomb_triggered' });
        reporter.report(ip, {
            protocol: 'ssh',
            port: cfg.port || 2222,
            comment: `SSH exec backup read attempt -> GZIP bomb triggered: ${command}`,
            categories: '22,18'
        }).catch(() => {});

        const chunk = crypto.randomBytes(65536);
        for (let c = 0; c < 150; c++) {
            if (stream.destroyed || stream.writableEnded) break;
            stream.write(chunk);
            await sleep(5, 15);
        }
        stream.write('\r\n');
        stream.exit(0);
        stream.end();
        return;
    }

    // 2c. Intercept SSH Command Tarpit in exec
    const lowerCommand = command.toLowerCase().trim();
    const isTarpitExec = lowerCommand.startsWith('ping') || lowerCommand.startsWith('find') || lowerCommand.startsWith('grep') || lowerCommand.startsWith('nmap') || lowerCommand.startsWith('masscan');

    if (isTarpitExec) {
        logger.warn(`SSH exec command tarpit triggered: ${sanitizeForLog(command)}`, { protocol: 'ssh', ip });
        logEvent({ protocol: 'ssh', ip, command, mode: 'exec', attack_type: 'ssh_command_tarpit_triggered' });
        reporter.report(ip, {
            protocol: 'ssh',
            port: cfg.port || 2222,
            comment: `SSH exec command tarpit triggered for command: "${command}"`,
            categories: '22,18'
        }).catch(() => {});

        const traps = require('../core/traps');
        traps.tarpitSSHCommand(stream, command, () => {
            stream.exit(0);
            stream.end();
        });
        return;
    }

    const canaryResponse = getCanaryResponse(command);
    const staticResponse = getStaticSSHResponse(command, sessionState);
    if (canaryResponse !== null) {
        await writeSSHOutput(stream, canaryResponse);
        stream.exit(0);
        stream.end();
        return;
    }
    if (staticResponse !== null) {
        if (staticResponse.length > 0) {
            await writeSSHOutput(stream, staticResponse);
        }
        stream.exit(0);
        stream.end();
        return;
    }

    const fsContext = getFSContext(command, sessionState);
    const response = await ai.generate({
        protocol: 'ssh',
        attackerInput: `Non-interactive exec command: ${command}`,
        context: { ip, port: cfg.port, fileContents: fsContext }
    });

    await writeSSHOutput(stream, response);
    stream.exit(0);
    stream.end();
}

// ─── SSH Tarpit (replaces Endlessh) ───────────────────────────────────────────
// Sends an infinite SSH banner — wastes bot time without any handshake
function startTarpit(port) {
    const srv = net.createServer((socket) => {
        const ip = socket.remoteAddress;
        logger.info(`Tarpit connection from ${ip}`, { protocol: 'tarpit' });

        if (global.activeConnections && global.activeConnections.tarpit !== undefined) {
            global.activeConnections.tarpit++;
        }
        let decremented = false;
        const decrement = () => {
            if (!decremented) {
                decremented = true;
                if (global.activeConnections && global.activeConnections.tarpit !== undefined) {
                    global.activeConnections.tarpit--;
                }
            }
        };
        socket.on('close', decrement);
        socket.on('error', decrement);

        logEvent({ protocol: 'tarpit', ip, port });

        // Send fake SSH banner data every 10 seconds — traps bots that wait for handshake
        socket.write(`SSH-2.0-OpenSSH_${Math.floor(Math.random()*3+7)}.${Math.floor(Math.random()*9)}p1\r\n`);

        const interval = setInterval(() => {
            if (socket.destroyed) { clearInterval(interval); return; }
            // Endless random garbage to keep the connection alive
            const garbage = crypto.randomBytes(32).toString('hex');
            socket.write(`${garbage}\r\n`);
        }, 10000);

        socket.on('error',  () => clearInterval(interval));
        socket.on('close',  () => clearInterval(interval));
        socket.setTimeout(3600000); // Keep alive for up to 1 hour
    });

    // MED-01: Cap concurrent tarpit connections to prevent fd exhaustion
    srv.maxConnections = 500;

    srv.listen(port, '0.0.0.0', () => {
        logger.info(`SSH tarpit listening on :${port} (max 500 connections)`, { protocol: 'tarpit' });
    });
    srv.on('error', (e) => logger.error(`Tarpit :${port} error: ${e.message}`, { protocol: 'tarpit' }));
    return srv;
}

function resetSSHRateLimits() {
    SSH_CONNECTION_COUNTS.clear();
}

module.exports = { start, getCanaryResponse, loadHoneyFS, HONEYFS_DIR, getReferencedFiles, runFakeShell, resetSSHRateLimits, handleExecCommand };
