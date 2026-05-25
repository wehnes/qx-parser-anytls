/**
 * Quantumult X Resource Parser
 * 处理流程：
 * 1. 支持整体 Base64 订阅；
 * 2. 支持解码后的 ss://base64(method:password)@host:port#tag；
 * 3. 将 SS2022 风格条目转成 QX anytls= 格式；
 * 4. 同时保留 anytls:// 转换能力。
 */

const DEFAULT_TLS_HOST = "m10.music.126.net"; 
// 如果你的节点必须固定 SNI，例如 m10.music.126.net，就改成：
// const DEFAULT_TLS_HOST = "m10.music.126.net";

const DEFAULT_TLS_VERIFICATION_FALSE = true;
const DEFAULT_ALPN_HEX = "02683208687474702f312e31";
const CONVERT_SS2022_TO_ANYTLS = true;

function safeDecode(s) {
  try {
    return decodeURIComponent(s || "");
  } catch (e) {
    return s || "";
  }
}

function b64Normalize(s) {
  let b64 = String(s || "")
    .trim()
    .replace(/\s+/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  while (b64.length % 4) b64 += "=";
  return b64;
}

function b64DecodeBinary(s) {
  try {
    return atob(b64Normalize(s));
  } catch (e) {
    return "";
  }
}

function binaryToUtf8(bin) {
  try {
    return decodeURIComponent(
      bin.split("").map(function (c) {
        return "%" + c.charCodeAt(0).toString(16).padStart(2, "0");
      }).join("")
    );
  } catch (e) {
    return bin;
  }
}

function b64DecodeUtf8(s) {
  const bin = b64DecodeBinary(s);
  if (!bin) return "";
  return binaryToUtf8(bin);
}

function looksLikeBase64Subscription(text) {
  const compact = String(text || "").trim().replace(/\s+/g, "");

  if (!compact) return false;

  // 明显已经是明文订阅
  if (
    /^ss:\/\//i.test(String(text).trim()) ||
    /^anytls:\/\//i.test(String(text).trim()) ||
    /^anytls=/i.test(String(text).trim()) ||
    /^shadowsocks=/i.test(String(text).trim())
  ) {
    return false;
  }

  // Base64 字符集判断
  return /^[A-Za-z0-9+/_=-]+$/.test(compact) && compact.length > 16;
}

function decodeSubscriptionIfNeeded(content) {
  const raw = String(content || "");
  const trimmed = raw.trim();

  // 已经是明文协议列表
  if (
    /^ss:\/\//im.test(trimmed) ||
    /^anytls:\/\//im.test(trimmed) ||
    /^anytls=/im.test(trimmed) ||
    /^shadowsocks=/im.test(trimmed)
  ) {
    return raw;
  }

  // 关键修复：即使整体 Base64 有换行，也先去掉空白再解码
  if (looksLikeBase64Subscription(raw)) {
    const decoded = b64DecodeUtf8(raw);

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
  }

  return raw;
}

function parseQuery(qs) {
  const obj = {};
  if (!qs) return obj;

  qs.split("&").forEach(function (part) {
    if (!part) return;

    const idx = part.indexOf("=");
    let k = "";
    let v = "";

    if (idx === -1) {
      k = safeDecode(part);
    } else {
      k = safeDecode(part.slice(0, idx));
      v = safeDecode(part.slice(idx + 1));
    }

    obj[k] = v;
  });

  return obj;
}

function alpnToHex(alpn) {
  if (!alpn) return "";

  const protocols = alpn
    .split(",")
    .map(function (x) { return x.trim(); })
    .filter(Boolean);

  let hex = "";

  protocols.forEach(function (p) {
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
    const colon = hostPort.lastIndexOf(":");
    if (colon >= 0) {
      host = hostPort.slice(0, colon);
      port = hostPort.slice(colon + 1);
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
  const alpnHex = opts.alpnHex || DEFAULT_ALPN_HEX || "";

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

  if (opts.realityPubkey) {
    out.push(`reality-base64-pubkey=${opts.realityPubkey}`);
  }

  if (opts.realityShortid) {
    out.push(`reality-hex-shortid=${opts.realityShortid}`);
  }

  out.push("udp-relay=true");
  out.push(`tag=${tag}`);

  return out.join(", ");
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
      tag = safeDecode(main.slice(hashIndex + 1));
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

    const password = safeDecode(authority.slice(0, atIndex));
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
      alpnHex: alpnHex,
      realityPubkey: params.pbk || params.publicKey || "",
      realityShortid: params.sid || params.shortId || ""
    });
  } catch (e) {
    return line;
  }
}

function convertSs2022UriToAnytls(line) {
  const raw = line.trim();
  if (!raw.startsWith("ss://")) return line;
  if (!CONVERT_SS2022_TO_ANYTLS) return line;

  try {
    let body = raw.slice("ss://".length);
    let tag = "";

    const hashIndex = body.indexOf("#");
    if (hashIndex >= 0) {
      tag = safeDecode(body.slice(hashIndex + 1));
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

    const userInfo = b64DecodeUtf8(userInfoB64);
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

let content = decodeSubscriptionIfNeeded($resource.content || "");

let converted = content
  .split(/\r?\n/)
  .map(function (line) {
    const trimmed = line.trim();

    if (!trimmed) return line;

    if (trimmed.startsWith("anytls://")) {
      return convertAnytlsUri(trimmed);
    }

    if (trimmed.startsWith("ss://")) {
      return convertSs2022UriToAnytls(trimmed);
    }

    return line;
  })
  .join("\n");

$done({ content: converted });
