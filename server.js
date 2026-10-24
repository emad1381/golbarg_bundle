'use strict';

const http = require('http');
const net = require('net');
const dns = require('dns');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const tls = require('tls');

const VERSION = '3.0.0';
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY_BYTES = 16 * 1024;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const LOGIN_MAX_FAILS = 5;
const LOGIN_LOCK_MS = 10 * 60 * 1000;
const EVENT_LIMIT = 100;

function parseIntEnv(name, def, min, max) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) {
    console.error(`[config] Invalid ${name}="${raw}" — expected an integer between ${min} and ${max}. Refusing to boot.`);
    process.exit(1);
  }
  return n;
}

function isValidHost(host) {
  return (
    typeof host === 'string' &&
    host.length >= 1 &&
    host.length <= 253 &&
    /^[A-Za-z0-9._:\-]+$/.test(host) &&
    !host.startsWith('-') &&
    !host.startsWith('.') &&
    !host.includes('..')
  );
}

const BIND_ADDR = process.env.SVC_HOST || '0.0.0.0';
const PANEL_PORT = parseIntEnv('PORT', 3000, 1, 65535);
const DATA_PORT = parseIntEnv('SVC_PORT', 8000, 1, 65535);
const EXT_HOST = (process.env.EXT_HOST || '52.28.89.209').trim();
const EXT_PORT = parseIntEnv('EXT_PORT', 6552, 1, 65535);
const MAX_CONN = parseIntEnv('MAX_CONN', 512, 1, 100000);
const IDLE_MS = parseIntEnv('IDLE_MS', 120000, 1000, 3600000);
const CONN_MS = parseIntEnv('CONN_MS', 10000, 1000, 120000);
const HEALTH_MS = parseIntEnv('HEALTH_MS', 30000, 1000, 600000);
const SVC_PATH = (process.env.SVC_PATH || '/assets/d3c8a91f').trim();
const EXT_WPORT = (process.env.EXT_WPORT === undefined || process.env.EXT_WPORT === '')
  ? 0
  : parseIntEnv('EXT_WPORT', 0, 1, 65535);
const EXT_WTLS = process.env.EXT_WTLS === '1';
const EXT_WHOST = (process.env.EXT_WHOST || '').trim();
const STREAM_ENABLED = EXT_WPORT > 0;

if (!isValidHost(EXT_HOST)) {
  console.error(`[config] Invalid EXT_HOST="${EXT_HOST}". Refusing to boot.`);
  process.exit(1);
}
if (PANEL_PORT === DATA_PORT) {
  console.error('[config] PORT and SVC_PORT must be different. Refusing to boot.');
  process.exit(1);
}
if (!SVC_PATH.startsWith('/') || SVC_PATH === '/' || SVC_PATH === '/healthz' || SVC_PATH.startsWith('/api/')) {
  console.error(`[config] Invalid SVC_PATH="${SVC_PATH}". Refusing to boot.`);
  process.exit(1);
}
if (EXT_WHOST && !isValidHost(EXT_WHOST)) {
  console.error(`[config] Invalid EXT_WHOST="${EXT_WHOST}". Refusing to boot.`);
  process.exit(1);
}

let ADMIN_PASS = process.env.ADMIN_PASS || '';
const passwordSource = ADMIN_PASS ? 'environment' : 'generated';
if (!ADMIN_PASS) {
  ADMIN_PASS = crypto.randomBytes(18).toString('base64url');
  console.log('');
  console.log('================================================================');
  console.log('[security] ADMIN_PASS is NOT set in the environment.');
  console.log(`[security] Generated admin password for THIS run: ${ADMIN_PASS}`);
  console.log('[security] Set ADMIN_PASS in the service env vars');
  console.log('[security] (متغیرهای محیطی) to use a fixed password you choose.');
  console.log('================================================================');
  console.log('');
} else if (ADMIN_PASS.length < 8) {
  console.log('[security] WARNING: ADMIN_PASS is shorter than 8 characters.');
}

function passwordMatches(candidate) {
  if (typeof candidate !== 'string') return false;
  const a = Buffer.from(candidate);
  const b = Buffer.from(ADMIN_PASS);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

const state = {
  startedAt: Date.now(),
  paused: false,
  target: { host: EXT_HOST, port: EXT_PORT },
  wsTarget: { host: EXT_HOST, port: EXT_WPORT },
  totalConnections: 0,
  rejectedConnections: 0,
  failedConnections: 0,
  bytesUp: 0,
  bytesDown: 0,
  lastError: null,
  remote: { reachable: false, pingMs: null, lastError: null, lastCheckAt: null },
  wsRemote: { reachable: false, pingMs: null, lastError: null, lastCheckAt: null },
};

const connections = new Map();
let connectionSeq = 0;
const sessions = new Map();
const loginAttempts = new Map();
const events = [];

function timestamp() {
  return new Date().toISOString();
}

function log(level, message) {
  const line = `[${timestamp()}] [${level}] ${message}`;
  if (level === 'error') console.error(line);
  else console.log(line);
}

function addEvent(level, message) {
  events.push({ t: Date.now(), level, message });
  if (events.length > EVENT_LIMIT) events.splice(0, events.length - EVENT_LIMIT);
}

function recordEvent(level, message) {
  log(level, message);
  addEvent(level, message);
}

function noteError(where, err) {
  const message = err && err.message ? err.message : String(err);
  state.lastError = `${where}: ${message}`;
  log('error', `${where}: ${message}`);
}

const DNS_TTL_MS = 60 * 1000;
const dnsCache = new Map();

function resolveHost(host, cb) {
  const ipVersion = net.isIP(host);
  if (ipVersion) return cb(null, { address: host, family: ipVersion });
  const hit = dnsCache.get(host);
  if (hit && hit.expiresAt > Date.now()) return cb(null, hit);
  dns.lookup(host, (err, address, family) => {
    if (err) return cb(err);
    const entry = { address, family, expiresAt: Date.now() + DNS_TTL_MS };
    dnsCache.set(host, entry);
    cb(null, entry);
  });
}

function probeSocket(target, done) {
  const started = Date.now();
  resolveHost(target.host, (err, resolved) => {
    if (err) return done(false, null, `DNS: ${err.message}`);
    const socket = new net.Socket();
    let settled = false;
    const finish = (ok, probeErr) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      done(ok, ok ? Date.now() - started : null, ok ? null : probeErr ? probeErr.message : 'timeout');
    };
    socket.setTimeout(CONN_MS);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false, new Error(`probe timeout after ${CONN_MS} ms`)));
    socket.once('error', (e) => finish(false, e));
    socket.connect(target.port, resolved.address);
  });
}

function probeRemote() {
  const { host, port } = state.target;
  probeSocket(state.target, (ok, pingMs, errMessage) => {
    const wasReachable = state.remote.reachable;
    state.remote.reachable = ok;
    state.remote.pingMs = pingMs;
    state.remote.lastError = ok ? null : errMessage;
    state.remote.lastCheckAt = Date.now();
    if (ok && !wasReachable) recordEvent('info', `Remote reachable / سرور خارج در دسترس شد: ${host}:${port} (${pingMs} ms)`);
    if (!ok && wasReachable) recordEvent('warn', `Remote unreachable / سرور خارج از دسترس خارج شد: ${host}:${port} — ${errMessage}`);
  });
}

function probeStream() {
  if (!STREAM_ENABLED) return;
  const { host, port } = state.wsTarget;
  probeSocket(state.wsTarget, (ok, pingMs, errMessage) => {
    const wasReachable = state.wsRemote.reachable;
    state.wsRemote.reachable = ok;
    state.wsRemote.pingMs = pingMs;
    state.wsRemote.lastError = ok ? null : errMessage;
    state.wsRemote.lastCheckAt = Date.now();
    if (ok && !wasReachable) recordEvent('info', `Stream reachable: ${host}:${port} (${pingMs} ms)`);
    if (!ok && wasReachable) recordEvent('warn', `Stream unreachable: ${host}:${port} — ${errMessage}`);
  });
}

const BUF_SIZE = 256 * 1024;
const SWEEP_INTERVAL_MS = 5000;

const dataServer = net.createServer(
  { allowHalfOpen: false, pauseOnConnect: true, highWaterMark: BUF_SIZE },
  (clientSocket) => {
    const clientAddr = `${clientSocket.remoteAddress || '?'}:${clientSocket.remotePort || '?'}`;

    if (state.paused) {
      state.rejectedConnections++;
      log('warn', `Service paused — refused connection from ${clientAddr}`);
      clientSocket.destroy();
      return;
    }
    if (connections.size >= MAX_CONN) {
      state.rejectedConnections++;
      recordEvent('warn', `Connection cap reached (${MAX_CONN}) — refused ${clientAddr}`);
      clientSocket.destroy();
      return;
    }

    const id = `c${++connectionSeq}`;
    const target = { host: state.target.host, port: state.target.port };
    const now = Date.now();

    const rec = {
      id,
      client: clientAddr,
      targetHost: target.host,
      targetPort: target.port,
      startedAt: now,
      lastActivity: now,
      bytesUp: 0,
      bytesDown: 0,
      state: 'connecting',
      clientSocket,
      remoteSocket: null,
      kill: null,
    };
    connections.set(id, rec);
    state.totalConnections++;

    clientSocket.setNoDelay(true);
    clientSocket.setKeepAlive(true, 15000);

    let tornDown = false;
    const teardown = () => {
      if (tornDown) return;
      tornDown = true;
      connections.delete(id);
      if (rec.remoteSocket) {
        clientSocket.unpipe(rec.remoteSocket);
        rec.remoteSocket.unpipe(clientSocket);
        rec.remoteSocket.destroy();
      }
      clientSocket.destroy();
    };
    rec.kill = teardown;

    clientSocket.on('error', (err) => {
      log('warn', `Client socket error #${id} (${clientAddr}): ${err.message}`);
      teardown();
    });
    clientSocket.on('close', teardown);

    resolveHost(target.host, (dnsErr, resolved) => {
      if (tornDown) return;
      if (dnsErr) {
        state.failedConnections++;
        state.lastError = `DNS ${target.host}: ${dnsErr.message}`;
        recordEvent('warn', `DNS lookup failed for ${target.host} (#${id}, ${clientAddr}): ${dnsErr.message}`);
        teardown();
        return;
      }

      const remoteSocket = net.connect({
        host: resolved.address,
        port: target.port,
        family: resolved.family,
        allowHalfOpen: false,
        highWaterMark: BUF_SIZE,
      });
      rec.remoteSocket = remoteSocket;
      remoteSocket.setNoDelay(true);
      remoteSocket.setKeepAlive(true, 15000);

      remoteSocket.on('error', (err) => {
        if (rec.state === 'connecting') {
          state.failedConnections++;
          dnsCache.delete(target.host);
          state.lastError = `connect ${target.host}:${target.port}: ${err.message}`;
          recordEvent('warn', `Remote connect failed #${id} -> ${target.host}:${target.port}: ${err.message}`);
        } else {
          state.lastError = `remote ${target.host}:${target.port}: ${err.message}`;
          log('warn', `Remote socket error #${id} -> ${target.host}:${target.port}: ${err.message}`);
        }
        teardown();
      });
      remoteSocket.on('close', teardown);

      remoteSocket.once('connect', () => {
        if (tornDown) return;
        rec.state = 'open';
        clientSocket.on('data', (chunk) => {
          rec.bytesUp += chunk.length;
          state.bytesUp += chunk.length;
          rec.lastActivity = Date.now();
        });
        remoteSocket.on('data', (chunk) => {
          rec.bytesDown += chunk.length;
          state.bytesDown += chunk.length;
          rec.lastActivity = Date.now();
        });
        clientSocket.pipe(remoteSocket);
        remoteSocket.pipe(clientSocket);
        log('info', `Channel #${id}: ${clientAddr} -> ${target.host}:${target.port}`);
      });
    });
  }
);
dataServer.maxConnections = MAX_CONN;

dataServer.on('error', (err) => {
  noteError('data server', err);
  if (err.code === 'EADDRINUSE') process.exit(1);
});

setInterval(() => {
  const now = Date.now();
  for (const rec of connections.values()) {
    if (rec.state === 'connecting' && now - rec.startedAt > CONN_MS) {
      state.failedConnections++;
      state.lastError = `connect timeout to ${rec.targetHost}:${rec.targetPort}`;
      recordEvent('warn', `Connect timeout to ${rec.targetHost}:${rec.targetPort} for #${rec.id} (${rec.client})`);
      rec.kill();
    } else if (rec.state === 'open' && now - rec.lastActivity > IDLE_MS) {
      recordEvent('warn', `Idle timeout (${IDLE_MS} ms) — closed #${rec.id} (${rec.client})`);
      rec.kill();
    }
  }
}, SWEEP_INTERVAL_MS).unref();

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_FRAME_BYTES = 64 * 1024 * 1024;

function wsAcceptKey(key) {
  return crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
}

function wsBuildFrame(opcode, payload, maskKey) {
  const len = payload.length;
  let headerSize = 2;
  if (len > 65535) headerSize += 8;
  else if (len >= 126) headerSize += 2;
  if (maskKey) headerSize += 4;
  const frame = Buffer.alloc(headerSize + len);
  frame[0] = 0x80 | opcode;
  let offset = 2;
  if (len < 126) {
    frame[1] = len;
  } else if (len <= 65535) {
    frame[1] = 126;
    frame.writeUInt16BE(len, 2);
    offset = 4;
  } else {
    frame[1] = 127;
    frame.writeBigUInt64BE(BigInt(len), 2);
    offset = 10;
  }
  if (maskKey) {
    frame[1] |= 0x80;
    maskKey.copy(frame, offset);
    offset += 4;
    for (let i = 0; i < len; i++) frame[offset + i] = payload[i] ^ maskKey[i & 3];
  } else if (len) {
    payload.copy(frame, offset);
  }
  return frame;
}

function makeFrameParser(handlers) {
  let buffer = Buffer.alloc(0);
  let fragOpcode = -1;
  let fragParts = [];
  let fragBytes = 0;
  let dead = false;
  const fail = (err) => {
    if (dead) return;
    dead = true;
    handlers.onError(err);
  };
  return {
    push(chunk) {
      if (dead || !chunk || !chunk.length) return;
      buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk;
      for (;;) {
        if (buffer.length < 2) return;
        const first = buffer[0];
        const second = buffer[1];
        const fin = (first & 0x80) !== 0;
        const opcode = first & 0x0f;
        const masked = (second & 0x80) !== 0;
        let length = second & 0x7f;
        let offset = 2;
        if (length === 126) {
          if (buffer.length < 4) return;
          length = buffer.readUInt16BE(2);
          offset = 4;
        } else if (length === 127) {
          if (buffer.length < 10) return;
          const wide = buffer.readBigUInt64BE(2);
          if (wide > BigInt(MAX_FRAME_BYTES)) return fail(new Error('frame too large'));
          length = Number(wide);
          offset = 10;
        }
        let maskKey = null;
        if (masked) {
          if (buffer.length < offset + 4) return;
          maskKey = buffer.subarray(offset, offset + 4);
          offset += 4;
        }
        if (buffer.length < offset + length) return;
        let payload;
        if (maskKey) {
          payload = Buffer.alloc(length);
          for (let i = 0; i < length; i++) payload[i] = buffer[offset + i] ^ maskKey[i & 3];
        } else {
          payload = Buffer.from(buffer.subarray(offset, offset + length));
        }
        buffer = buffer.subarray(offset + length);
        if (opcode === 8) {
          dead = true;
          handlers.onCloseFrame(payload);
          return;
        }
        if (opcode === 9) {
          handlers.onPing(payload);
          continue;
        }
        if (opcode === 10) {
          handlers.onPong(payload);
          continue;
        }
        if (opcode === 0) {
          if (fragOpcode === -1) return fail(new Error('unexpected continuation frame'));
          fragParts.push(payload);
          fragBytes += payload.length;
          if (fragBytes > MAX_FRAME_BYTES) return fail(new Error('message too large'));
          if (fin) {
            const whole = Buffer.concat(fragParts, fragBytes);
            fragOpcode = -1;
            fragParts = [];
            fragBytes = 0;
            handlers.onMessage(whole);
          }
          continue;
        }
        if (opcode === 1 || opcode === 2) {
          if (fragOpcode !== -1) return fail(new Error('data frame inside fragmented message'));
          if (!fin) {
            fragOpcode = opcode;
            fragParts = [payload];
            fragBytes = payload.length;
            continue;
          }
          handlers.onMessage(payload);
          continue;
        }
        return fail(new Error(`unsupported frame opcode ${opcode}`));
      }
    },
  };
}

function writeFrame(sock, frame, sourceSock) {
  if (!sock || sock.destroyed) return;
  const flushed = sock.write(frame);
  if (!flushed && sourceSock && !sourceSock.destroyed) {
    sourceSock.pause();
    sock.once('drain', () => {
      if (!sourceSock.destroyed) sourceSock.resume();
    });
  }
}

function openStreamChannel(req, clientSocket, head) {
  const clientAddr = `${clientSocket.remoteAddress || '?'}:${clientSocket.remotePort || '?'}`;
  const id = `s${++connectionSeq}`;
  const now = Date.now();
  const target = { host: state.wsTarget.host, port: state.wsTarget.port };
  const rec = {
    id,
    client: clientAddr,
    targetHost: target.host,
    targetPort: target.port,
    startedAt: now,
    lastActivity: now,
    bytesUp: 0,
    bytesDown: 0,
    state: 'connecting',
    clientSocket,
    remoteSocket: null,
    kill: null,
  };
  connections.set(id, rec);
  state.totalConnections++;

  clientSocket.setNoDelay(true);
  clientSocket.setKeepAlive(true, 15000);

  let tornDown = false;
  let handshakeDone = false;
  let clientCloseSent = false;
  let remoteCloseSent = false;
  let remoteSocket = null;
  const pendingClientChunks = [];
  if (head && head.length) pendingClientChunks.push(Buffer.from(head));

  const teardown = () => {
    if (tornDown) return;
    tornDown = true;
    connections.delete(id);
    try { clientSocket.destroy(); } catch {}
    if (remoteSocket) {
      try { remoteSocket.destroy(); } catch {}
    }
  };
  rec.kill = teardown;

  const failBeforeOpen = () => {
    if (tornDown) return;
    tornDown = true;
    connections.delete(id);
    try {
      clientSocket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    } catch {}
    if (remoteSocket) {
      try { remoteSocket.destroy(); } catch {}
    }
    setTimeout(() => {
      try { clientSocket.destroy(); } catch {}
    }, 250).unref();
  };

  const endGracefully = () => {
    setTimeout(teardown, 1000).unref();
  };

  const remoteParser = makeFrameParser({
    onMessage(payload) {
      rec.bytesDown += payload.length;
      state.bytesDown += payload.length;
      rec.lastActivity = Date.now();
      writeFrame(clientSocket, wsBuildFrame(2, payload, null), remoteSocket);
    },
    onPing(payload) {
      writeFrame(remoteSocket, wsBuildFrame(10, payload, crypto.randomBytes(4)), null);
    },
    onPong() {},
    onCloseFrame(payload) {
      if (!clientCloseSent && !clientSocket.destroyed) {
        clientCloseSent = true;
        try { clientSocket.end(wsBuildFrame(8, payload, null)); } catch {}
      }
      if (remoteSocket && !remoteSocket.destroyed) {
        try { remoteSocket.end(); } catch {}
      }
      endGracefully();
    },
    onError(err) {
      state.lastError = `stream remote ${target.host}:${target.port}: ${err.message}`;
      log('warn', `Stream frame error #${id} from remote: ${err.message}`);
      teardown();
    },
  });

  const clientParser = makeFrameParser({
    onMessage(payload) {
      rec.bytesUp += payload.length;
      state.bytesUp += payload.length;
      rec.lastActivity = Date.now();
      writeFrame(remoteSocket, wsBuildFrame(2, payload, crypto.randomBytes(4)), clientSocket);
    },
    onPing(payload) {
      writeFrame(clientSocket, wsBuildFrame(10, payload, null), null);
    },
    onPong() {},
    onCloseFrame(payload) {
      if (!clientCloseSent && !clientSocket.destroyed) {
        clientCloseSent = true;
        try { clientSocket.end(wsBuildFrame(8, payload, null)); } catch {}
      }
      if (remoteSocket && !remoteSocket.destroyed && !remoteCloseSent) {
        remoteCloseSent = true;
        try { remoteSocket.end(wsBuildFrame(8, payload, crypto.randomBytes(4))); } catch {}
      }
      endGracefully();
    },
    onError(err) {
      state.lastError = `stream client ${clientAddr}: ${err.message}`;
      log('warn', `Stream frame error #${id} from client: ${err.message}`);
      teardown();
    },
  });

  clientSocket.on('data', (chunk) => {
    rec.lastActivity = Date.now();
    if (rec.state === 'open') clientParser.push(chunk);
    else pendingClientChunks.push(chunk);
  });
  clientSocket.on('error', (err) => {
    log('warn', `Client socket error #${id} (${clientAddr}): ${err.message}`);
    teardown();
  });
  clientSocket.on('close', teardown);

  resolveHost(target.host, (dnsErr, resolved) => {
    if (tornDown) return;
    if (dnsErr) {
      state.failedConnections++;
      state.lastError = `DNS ${target.host}: ${dnsErr.message}`;
      recordEvent('warn', `DNS lookup failed for ${target.host} (#${id}, ${clientAddr}): ${dnsErr.message}`);
      failBeforeOpen();
      return;
    }

    const onRemoteError = (err) => {
      if (!handshakeDone) {
        state.failedConnections++;
        dnsCache.delete(target.host);
        state.lastError = `stream connect ${target.host}:${target.port}: ${err.message}`;
        recordEvent('warn', `Stream connect failed #${id} -> ${target.host}:${target.port}: ${err.message}`);
        failBeforeOpen();
      } else {
        state.lastError = `stream remote ${target.host}:${target.port}: ${err.message}`;
        log('warn', `Stream remote socket error #${id}: ${err.message}`);
        teardown();
      }
    };

    const beginHandshake = () => {
      if (tornDown || handshakeDone) return;
      const key = crypto.randomBytes(16).toString('base64');
      const hostHeader = EXT_WHOST || `${target.host}:${target.port}`;
      const request =
        `GET ${SVC_PATH} HTTP/1.1\r\n` +
        `Host: ${hostHeader}\r\n` +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Key: ${key}\r\n` +
        'Sec-WebSocket-Version: 13\r\n\r\n';
      let received = Buffer.alloc(0);
      const onHandshakeData = (chunk) => {
        received = received.length ? Buffer.concat([received, chunk]) : chunk;
        const boundary = received.indexOf('\r\n\r\n');
        if (boundary === -1) {
          if (received.length > 16384) {
            state.lastError = 'stream handshake overflow';
            teardown();
          }
          return;
        }
        remoteSocket.removeListener('data', onHandshakeData);
        const headerText = received.subarray(0, boundary).toString('latin1');
        const statusLine = headerText.split('\r\n')[0] || '';
        if (!/^HTTP\/1\.1 101/.test(statusLine)) {
          state.failedConnections++;
          state.lastError = `stream handshake rejected: ${statusLine}`;
          recordEvent('warn', `Stream handshake rejected #${id} -> ${target.host}:${target.port}: ${statusLine}`);
          failBeforeOpen();
          return;
        }
        handshakeDone = true;
        const clientKey = req.headers['sec-websocket-key'];
        try {
          clientSocket.write(
            'HTTP/1.1 101 Switching Protocols\r\n' +
            'Upgrade: websocket\r\n' +
            'Connection: Upgrade\r\n' +
            `Sec-WebSocket-Accept: ${wsAcceptKey(clientKey)}\r\n\r\n`
          );
        } catch {
          teardown();
          return;
        }
        rec.state = 'open';
        log('info', `Channel #${id}: ${clientAddr} -> ${target.host}:${target.port} (stream)`);
        const rest = received.subarray(boundary + 4);
        remoteSocket.on('data', (dataChunk) => {
          rec.lastActivity = Date.now();
          remoteParser.push(dataChunk);
        });
        if (rest.length) remoteParser.push(rest);
        for (const pending of pendingClientChunks) clientParser.push(pending);
        pendingClientChunks.length = 0;
      };
      remoteSocket.on('data', onHandshakeData);
      remoteSocket.write(request);
    };

    if (EXT_WTLS) {
      const tlsOptions = { host: resolved.address, port: target.port, family: resolved.family, allowHalfOpen: false };
      const serverName = EXT_WHOST || (net.isIP(target.host) ? '' : target.host);
      if (serverName) tlsOptions.servername = serverName;
      remoteSocket = tls.connect(tlsOptions);
      remoteSocket.once('secureConnect', beginHandshake);
    } else {
      remoteSocket = net.connect({ host: resolved.address, port: target.port, family: resolved.family, allowHalfOpen: false });
      remoteSocket.once('connect', beginHandshake);
    }
    rec.remoteSocket = remoteSocket;
    remoteSocket.setNoDelay(true);
    remoteSocket.setKeepAlive(true, 15000);
    remoteSocket.on('error', onRemoteError);
    remoteSocket.on('close', teardown);
  });
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    ...extraHeaders,
  });
  res.end(body);
}

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie;
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    try {
      out[key] = decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      out[key] = part.slice(eq + 1).trim();
    }
  }
  return out;
}

function isAuthenticated(req) {
  const token = parseCookies(req).session;
  if (!token) return false;
  const expiresAt = sessions.get(token);
  if (!expiresAt) return false;
  if (Date.now() > expiresAt) {
    sessions.delete(token);
    return false;
  }
  return true;
}

function readJsonBody(req, res, onBody) {
  const chunks = [];
  let size = 0;
  let aborted = false;
  req.on('data', (chunk) => {
    if (aborted) return;
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      aborted = true;
      sendJson(res, 413, { ok: false, error: 'request_too_large' });
      req.destroy();
      return;
    }
    chunks.push(chunk);
  });
  req.on('end', () => {
    if (aborted) return;
    const raw = Buffer.concat(chunks).toString('utf8').trim();
    if (!raw) return onBody({});
    try {
      onBody(JSON.parse(raw));
    } catch {
      sendJson(res, 400, { ok: false, error: 'invalid_json' });
    }
  });
  req.on('error', () => {});
}

function statusPayload() {
  return {
    ok: true,
    mode: 'pipe',
    version: VERSION,
    paused: state.paused,
    state: state.paused ? 'paused' : 'live',
    listen: { host: BIND_ADDR, panelPort: PANEL_PORT, dataPort: DATA_PORT },
    wsPath: SVC_PATH,
    wsTarget: STREAM_ENABLED ? `${state.wsTarget.host}:${state.wsTarget.port}` : null,
    stream: {
      enabled: STREAM_ENABLED,
      path: SVC_PATH,
      host: state.wsTarget.host,
      port: state.wsTarget.port,
      secure: EXT_WTLS,
      reachable: state.wsRemote.reachable,
      pingMs: state.wsRemote.pingMs,
      lastError: state.wsRemote.lastError,
      lastCheckAt: state.wsRemote.lastCheckAt,
    },
    target: { host: state.target.host, port: state.target.port },
    remote: {
      reachable: state.remote.reachable,
      pingMs: state.remote.pingMs,
      lastError: state.remote.lastError,
      lastCheckAt: state.remote.lastCheckAt,
    },
    uptimeSec: Math.floor((Date.now() - state.startedAt) / 1000),
    connections: {
      active: connections.size,
      total: state.totalConnections,
      rejected: state.rejectedConnections,
      failed: state.failedConnections,
      max: MAX_CONN,
    },
    traffic: { up: state.bytesUp, down: state.bytesDown },
    lastError: state.lastError,
    events: [...events].reverse(),
  };
}

function connectionsPayload() {
  const now = Date.now();
  return {
    ok: true,
    connections: [...connections.values()].map((rec) => ({
      id: rec.id,
      client: rec.client,
      target: `${rec.targetHost}:${rec.targetPort}`,
      startedAt: rec.startedAt,
      ageSec: Math.floor((now - rec.startedAt) / 1000),
      bytesUp: rec.bytesUp,
      bytesDown: rec.bytesDown,
      state: rec.state,
    })),
  };
}

function handleLogin(req, res) {
  const ip = req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const attempts = loginAttempts.get(ip) || { fails: 0, lockedUntil: 0 };

  if (attempts.lockedUntil > now) {
    const retryAfterSec = Math.ceil((attempts.lockedUntil - now) / 1000);
    return sendJson(
      res,
      429,
      { ok: false, error: 'too_many_attempts', retryAfterSec },
      { 'Retry-After': String(retryAfterSec) }
    );
  }

  readJsonBody(req, res, (body) => {
    if (passwordMatches(body.password)) {
      loginAttempts.delete(ip);
      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, Date.now() + SESSION_TTL_MS);
      recordEvent('info', `Admin login from ${ip} / ورود مدیر`);
      return sendJson(res, 200, { ok: true }, {
        'Set-Cookie': `session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`,
      });
    }
    attempts.fails += 1;
    if (attempts.fails >= LOGIN_MAX_FAILS) {
      attempts.lockedUntil = Date.now() + LOGIN_LOCK_MS;
      attempts.fails = 0;
      recordEvent('warn', `Login locked for ${ip} after ${LOGIN_MAX_FAILS} failed attempts (10 min)`);
    }
    loginAttempts.set(ip, attempts);
    log('warn', `Failed login attempt from ${ip}`);
    return sendJson(res, 401, { ok: false, error: 'invalid_password' });
  });
}

function handleLogout(req, res) {
  const token = parseCookies(req).session;
  if (token) sessions.delete(token);
  sendJson(res, 200, { ok: true }, {
    'Set-Cookie': 'session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0',
  });
}

function handleState(req, res) {
  readJsonBody(req, res, (body) => {
    if (typeof body.paused !== 'boolean') {
      return sendJson(res, 400, { ok: false, error: 'paused_must_be_boolean' });
    }
    if (body.paused !== state.paused) {
      state.paused = body.paused;
      recordEvent(
        'info',
        state.paused
          ? 'Service paused / سرویس متوقف شد — new connections are refused, existing ones keep flowing'
          : 'Service resumed / سرویس فعال شد'
      );
    }
    return sendJson(res, 200, statusPayload());
  });
}

function handleTarget(req, res) {
  readJsonBody(req, res, (body) => {
    const host = typeof body.host === 'string' ? body.host.trim() : '';
    const port = Number(body.port);
    if (!isValidHost(host)) {
      return sendJson(res, 400, { ok: false, error: 'invalid_host' });
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return sendJson(res, 400, { ok: false, error: 'invalid_port' });
    }
    const changed = host !== state.target.host || port !== state.target.port;
    state.target = { host, port };
    if (changed) {
      recordEvent('info', `Target changed / مقصد تغییر کرد -> ${host}:${port} (new connections only)`);
      probeRemote();
    }
    return sendJson(res, 200, statusPayload());
  });
}

function handleStreamTarget(req, res) {
  readJsonBody(req, res, (body) => {
    if (!STREAM_ENABLED) {
      return sendJson(res, 400, { ok: false, error: 'stream_not_armed' });
    }
    const host = typeof body.host === 'string' ? body.host.trim() : '';
    const port = Number(body.port);
    if (!isValidHost(host)) {
      return sendJson(res, 400, { ok: false, error: 'invalid_host' });
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return sendJson(res, 400, { ok: false, error: 'invalid_port' });
    }
    const changed = host !== state.wsTarget.host || port !== state.wsTarget.port;
    state.wsTarget = { host, port };
    if (changed) {
      recordEvent('info', `Stream target changed -> ${host}:${port} (new connections only)`);
      probeStream();
    }
    return sendJson(res, 200, statusPayload());
  });
}

function handleKill(req, res) {
  readJsonBody(req, res, (body) => {
    const id = typeof body.id === 'string' ? body.id : '';
    const rec = connections.get(id);
    if (!rec) return sendJson(res, 404, { ok: false, error: 'connection_not_found' });
    recordEvent('info', `Connection #${rec.id} (${rec.client}) closed from panel / اتصال از پنل قطع شد`);
    rec.kill();
    return sendJson(res, 200, { ok: true });
  });
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.woff2': 'font/woff2',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const filePath = path.resolve(PUBLIC_DIR, rel);
  if (filePath !== PUBLIC_DIR && !filePath.startsWith(PUBLIC_DIR + path.sep)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Forbidden');
  }
  fs.stat(filePath, (err, st) => {
    if (err || !st.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Not Found');
    }
    const type = MIME_TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': type, 'Content-Length': st.size });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(filePath).pipe(res);
  });
}

const webServer = http.createServer((req, res) => {
  let pathname;
  try {
    pathname = new URL(req.url, 'http://localhost').pathname;
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Bad Request');
  }

  if (pathname === '/healthz' && req.method === 'GET') {
    return sendJson(res, 200, { status: 'ok' });
  }

  if (pathname === '/api/login' && req.method === 'POST') return handleLogin(req, res);

  if (pathname.startsWith('/api/')) {
    if (!isAuthenticated(req)) {
      return sendJson(res, 401, { ok: false, error: 'unauthorized' });
    }
    if (pathname === '/api/logout' && req.method === 'POST') return handleLogout(req, res);
    if (pathname === '/api/status' && req.method === 'GET') return sendJson(res, 200, statusPayload());
    if (pathname === '/api/connections' && req.method === 'GET') return sendJson(res, 200, connectionsPayload());
    if (pathname === '/api/connections/kill' && req.method === 'POST') return handleKill(req, res);
    if (pathname === '/api/state' && req.method === 'POST') return handleState(req, res);
    if (pathname === '/api/target' && req.method === 'POST') return handleTarget(req, res);
    if (pathname === '/api/stream-target' && req.method === 'POST') return handleStreamTarget(req, res);
    return sendJson(res, 404, { ok: false, error: 'not_found' });
  }

  if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, pathname);

  res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
  return res.end('Method Not Allowed');
});

webServer.on('error', (err) => {
  noteError('web server', err);
  if (err.code === 'EADDRINUSE') process.exit(1);
});

function refuseUpgrade(socket, statusLine) {
  try {
    socket.end(`HTTP/1.1 ${statusLine}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  } catch {}
  setTimeout(() => {
    try { socket.destroy(); } catch {}
  }, 250).unref();
}

webServer.on('upgrade', (req, socket, head) => {
  socket.on('error', () => {});
  let pathname = '';
  try {
    pathname = new URL(req.url, 'http://localhost').pathname;
  } catch {}
  if (!STREAM_ENABLED || pathname !== SVC_PATH) {
    refuseUpgrade(socket, '404 Not Found');
    return;
  }
  const key = req.headers['sec-websocket-key'];
  const upgradeHeader = String(req.headers.upgrade || '').toLowerCase();
  if (req.method !== 'GET' || upgradeHeader !== 'websocket' || typeof key !== 'string' || !key) {
    refuseUpgrade(socket, '400 Bad Request');
    return;
  }
  if (state.paused || connections.size >= MAX_CONN) {
    state.rejectedConnections++;
    if (state.paused) {
      log('warn', `Service paused — refused stream connection from ${socket.remoteAddress || '?'}`);
    } else {
      recordEvent('warn', `Connection cap reached (${MAX_CONN}) — refused stream connection`);
    }
    refuseUpgrade(socket, '503 Service Unavailable');
    return;
  }
  openStreamChannel(req, socket, head);
});

dataServer.listen(DATA_PORT, BIND_ADDR, () => {
  log('info', `Data channel listening on ${BIND_ADDR}:${DATA_PORT} -> ${state.target.host}:${state.target.port}`);
});
webServer.listen(PANEL_PORT, BIND_ADDR, () => {
  log('info', `Admin panel listening on http://${BIND_ADDR}:${PANEL_PORT}`);
});

log('info', `golbarg v${VERSION} starting…`);
log('info', `Config / کانفیگ: panel=:${PANEL_PORT} data=:${DATA_PORT} target=${state.target.host}:${state.target.port} maxConn=${MAX_CONN} idleMs=${IDLE_MS} connMs=${CONN_MS} healthMs=${HEALTH_MS} adminPass=${passwordSource} stream=${STREAM_ENABLED ? `${SVC_PATH}->${state.wsTarget.host}:${state.wsTarget.port}` : 'off'}`);
log('info', `Data plane: native socket .pipe() both directions, ${BUF_SIZE} B stream buffers, DNS cached ${DNS_TTL_MS} ms, shared ${SWEEP_INTERVAL_MS} ms idle sweep`);
recordEvent('info', `Service started / سرویس شروع به کار کرد — data :${DATA_PORT} -> ${state.target.host}:${state.target.port}`);
if (STREAM_ENABLED) {
  log('info', `Stream path ready: ${SVC_PATH} -> ${state.wsTarget.host}:${state.wsTarget.port}${EXT_WTLS ? ' (secure)' : ''}`);
}

probeRemote();
probeStream();
setInterval(() => {
  probeRemote();
  probeStream();
}, HEALTH_MS).unref();

let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  log('info', `${signal} received — shutting down gracefully…`);
  dataServer.close();
  webServer.close();
  for (const rec of [...connections.values()]) rec.kill();
  sessions.clear();
  setTimeout(() => process.exit(0), 250);
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  noteError('uncaughtException', err);
});
process.on('unhandledRejection', (reason) => {
  noteError('unhandledRejection', reason instanceof Error ? reason : new Error(String(reason)));
});
