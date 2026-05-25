/**
 * Quantumult X Resource Parser
 * Robust version without atob()
 *
 * 处理：
 * 1. 整体 Base64 订阅；
 * 2. 解出 ss://...；
 * 3. 再解 ss:// 里的 base64(method:password)；
 * 4. 转成 QX anytls=...
 */

const DEFAULT_TLS_HOST = "";
// 如果你确定所有节点必须用固定 SNI，例如之前手动成功的：
// const DEFAULT_TLS_HOST = "m10.music.126.net";

const DEFAULT_TLS_VERIFICATION_FALSE = true;
const DEFAULT_ALPN_HEX = "02683208687474702f312e31";

const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function safeDecodeURIComponent(s) {
  try {
    return decodeURIComponent(s || "");
  } catch (e) {
    return s || "";
  }
}

function normalizeBase64(input) {
  let s = String(input || "")
    .trim()
    .replace(/\s+/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  // 去掉明显不是 base64 的字符
  s = s.replace(/[^A-Za-z0-9+/=]/g, "");

  while (s.length % 4) s += "=";

  return s;
}

function base64DecodeBinary(input) {
  const str = normalizeBase64(input);
  let output = "";
  let buffer = 0;
  let bits = 0;

  for (let i = 0; i < str.length; i++) {
    const c = str.charAt(i);

    if (c === "=") break;

    const val = BASE64_CHARS.indexOf(c);
    if (val < 0) continue;

    buffer = (buffer << 6) | val;
    bits += 6;

    if (bits >= 8) {
      bits -= 8;
      output += String.fromCharCode((buffer >> bits) & 0xff);
    }
  }

  return output;
}

function binaryToUtf8(bin) {
  try {
    let percent = "";

    for (let i = 0; i < bin.length; i++) {
      percent += "%" + bin.charCodeAt(i).toString(16).padStart(2, "0");
    }

    return decodeURIComponent(percent);
  } catch (e) {
    return bin;
  }
}

function base64DecodeUtf8(input) {
  const bin = base64DecodeBinary(input);
  return binaryToUtf8(bin);
}

function decodeSubscription(content) {
  const raw = String(content || "").trim();

  if (
    /^ss:\/\//im.test(raw) ||
    /^anytls:\/\//im.test(raw) ||
    /^anytls=/im.test(raw) ||
    /^shadowsocks=/im.test(raw)
  ) {
    return raw;
  }

  const decoded = base64DecodeUtf8(raw);

  if (
    decoded &&
    (
      decoded.includes("ss://") ||
      decoded.includes("anytls://") ||
      decoded.includes("anytls=") ||
      decoded.includes("shadowsocks=")
    )
  ) {
    return decoded;
  }

  return raw;
}

function parseQuery(qs) {
  const obj = {};
  if (!qs) return obj;

  qs.split("&").forEach(function(part) {
    if (!part) return;

    const idx = part.indexOf("=");

    if (idx === -1) {
      obj[safeDecodeURIComponent(part)] = "";
    } else {
      const k = safeDecodeURIComponent(part.slice(0, idx));
      const v = safeDecodeURIComponent(part.slice(idx + 1));
      obj[k] = v;
    }
  });

  return obj;
}

function alpnToHex(alpn) {
  if (!alpn) return "";

  const protocols = alpn
    .split(",")
    .map(function(x) { return x.trim(); })
    .filter(Boolean);

  let hex = "";

  protocols.forEach(function(p) {
    if (p.length <= 0 || p.length > 255) return;

    hex += p.length.toString(16).padStart(2, "0");

    for (let i = 0; i < p.length; i++) {
      hex += p.charCodeAt(i).toString(16).padStart(2, "0");
    }
  });

  return hex;
}

function splitHostPort(hostPort) {
  let host = "";
  let port = "";

  if (!hostPort) return { host, port };

  if (hostPort.startsWith("[")) {
    const end = hostPort.indexOf("]");
    if (end >= 0) {
      host = hostPort.slice(0, end + 1);
      port = hostPort.slice(end + 2);
    }
  } else {
    const idx = hostPort.lastIndexOf(":");
    if (idx >= 0) {
      host = hostPort.slice(0, idx);
      port = hostPort.slice(idx + 1);
    } else {
      host = hostPort;
    }
  }

  return { host, port };
}

function buildQxAnytls(opts) {
  const host = opts.host || "";
  const port = opts.port || "";
  const password = opts.password || "";
  const tag = opts.tag || `${host}:${port}`;

  const tlsHost = opts.tlsHost || DEFAULT_TLS_HOST || host;
  const alpnHex = opts.alpnHex || DEFAULT_ALPN_HEX;

  const out = [];

  out.push(`anytls=${host}:${port}`);
  out.push(`password=${password}`);
  out.push("over-tls=true");

  if (tlsHost) {
    out.push(`tls-host=${tlsHost}`);
  }

  if (opts.tlsVerificationFalse || DEFAULT_TLS_VERIFICATION_FALSE) {
    out.push("tls-verification=false");
  }

  if (alpnHex) {
    out.push(`tls-alpn=${alpnHex}`);
    out.push("tls-no-session-ticket=true");
  }

  out.push("udp-relay=true");
  out.push(`tag=${tag}`);

  return out.join(", ");
}

function convertSs2022ToAnytls(line) {
  const raw = line.trim();
  if (!raw.startsWith("ss://")) return line;

  try {
    let body = raw.slice("ss://".length);
    let tag = "";

    const hashIndex = body.indexOf("#");
    if (hashIndex >= 0) {
      tag = safeDecodeURIComponent(body.slice(hashIndex + 1));
      body = body.slice(0, hashIndex);
    }

    let main = body;
    let query = "";

    const qIndex = body.indexOf("?");
    if (qIndex >= 0) {
      main = body.slice(0, qIndex);
      query = body.slice(qIndex + 1);
    }

    const atIndex = main.lastIndexOf("@");
    if (atIndex < 0) return line;

    const userInfoB64 = main.slice(0, atIndex);
    const hostPort = main.slice(atIndex + 1);

    const hp = splitHostPort(hostPort);
    const userInfo = base64DecodeUtf8(userInfoB64);

    if (!userInfo) return line;

    const firstColon = userInfo.indexOf(":");
    if (firstColon < 0) return line;

    const method = userInfo.slice(0, firstColon);
    const password = userInfo.slice(firstColon + 1);

    if (!/^2022-blake3-/i.test(method)) {
      return line;
    }

    const params = parseQuery(query);

    const sni = params.sni || params.host || params.tlsHost || "";
    const insecure = params.insecure === "1" || params.insecure === "true";
    const alpnHex = alpnToHex(params.alpn || "") || DEFAULT_ALPN_HEX;

    return buildQxAnytls({
      host: hp.host,
      port: hp.port,
      password: password,
      tag: tag,
      tlsHost: sni,
      tlsVerificationFalse: insecure,
      alpnHex: alpnHex
    });
  } catch (e) {
    return line;
  }
}

function convertAnytlsUri(line) {
  const raw = line.trim();
  if (!raw.startsWith("anytls://")) return line;

  try {
    const noScheme = raw.slice("anytls://".length);

    let main = noScheme;
    let tag = "";

    const hashIndex = main.indexOf("#");
    if (hashIndex >= 0) {
      tag = safeDecodeURIComponent(main.slice(hashIndex + 1));
      main = main.slice(0, hashIndex);
    }

    let authority = main;
    let query = "";

    const qIndex = main.indexOf("?");
    if (qIndex >= 0) {
      authority = main.slice(0, qIndex);
      query = main.slice(qIndex + 1);
    }

    const atIndex = authority.lastIndexOf("@");
    if (atIndex < 0) return line;

    const password = safeDecodeURIComponent(authority.slice(0, atIndex));
    const hostPort = authority.slice(atIndex + 1);
    const hp = splitHostPort(hostPort);

    const params = parseQuery(query);

    const sni = params.sni || params.host || params.tlsHost || "";
    const insecure = params.insecure === "1" || params.insecure === "true";
    const alpnHex = alpnToHex(params.alpn || "") || DEFAULT_ALPN_HEX;

    return buildQxAnytls({
      host: hp.host,
      port: hp.port,
      password: password,
      tag: tag,
      tlsHost: sni,
      tlsVerificationFalse: insecure,
      alpnHex: alpnHex
    });
  } catch (e) {
    return line;
  }
}

let content = decodeSubscription($resource.content || "");

let converted = content
  .split(/\r?\n/)
  .map(function(line) {
    const trimmed = line.trim();

    if (!trimmed) return "";

    if (trimmed.startsWith("ss://")) {
      return convertSs2022ToAnytls(trimmed);
    }

    if (trimmed.startsWith("anytls://")) {
      return convertAnytlsUri(trimmed);
    }

    return line;
  })
  .filter(Boolean)
  .join("\n");

$done({ content: converted });
