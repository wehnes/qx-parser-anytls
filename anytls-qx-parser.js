/**
 * Quantumult X Resource Parser
 * Convert:
 *   1. anytls://password@host:port/?sni=xxx&insecure=1&alpn=h2,http/1.1#tag
 *   2. ss://base64(2022-blake3-aes-256-gcm:password)@host:port#tag
 * to Quantumult X anytls= format.
 */

/**
 * 如果你的服务端必须指定固定 SNI，在这里填。
 * 例如你之前那条可用配置里是 m10.music.126.net，就填：
 * const DEFAULT_TLS_HOST = "m10.music.126.net";
 *
 * 如果不确定，先留空，parser 会默认用服务器域名作为 tls-host。
 */
const DEFAULT_TLS_HOST = "m10.music.126.net";

/**
 * 是否默认跳过 TLS 证书验证。
 * 你之前的 anytls URI 有 insecure=1，所以这里默认 false verification。
 */
const DEFAULT_TLS_VERIFICATION_FALSE = true;

/**
 * 是否默认加 h2,http/1.1 ALPN。
 * 你之前能连的关键字段就是这个，所以默认开启。
 */
const DEFAULT_ALPN_HEX = "02683208687474702f312e31";

/**
 * 是否把 ss:// 里 2022-blake3-aes-256-gcm 节点强制转成 anytls。
 */
const CONVERT_SS2022_TO_ANYTLS = true;

function safeDecode(s) {
  try {
    return decodeURIComponent(s || "");
  } catch (e) {
    return s || "";
  }
}

function b64Normalize(s) {
  let b64 = (s || "").replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return b64;
}

function b64DecodeUtf8(s) {
  try {
    const bin = atob(b64Normalize(s));
    try {
      return decodeURIComponent(
        bin.split("").map(c => {
          return "%" + c.charCodeAt(0).toString(16).padStart(2, "0");
        }).join("")
      );
    } catch (e) {
      return bin;
    }
  } catch (e) {
    return "";
  }
}

function maybeBase64DecodeSubscription(content) {
  const text = (content || "").trim();

  // 已经是明文订阅
  if (
    /^anytls:\/\//im.test(text) ||
    /^ss:\/\//im.test(text) ||
    /^anytls=/im.test(text) ||
    /^shadowsocks=/im.test(text) ||
    text.includes("\n")
  ) {
    return content;
  }

  // 尝试整体 base64 订阅
  const decoded = b64DecodeUtf8(text);
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

  return content;
}

function parseQuery(qs) {
  const obj = {};
  if (!qs) return obj;

  qs.split("&").forEach(part => {
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
    .map(x => x.trim())
    .filter(Boolean);

  let hex = "";

  protocols.forEach(p => {
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

  // IPv6: [::1]:443
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

  let tlsHost = opts.tlsHost || DEFAULT_TLS_HOST || host;
  let alpnHex = opts.alpnHex || DEFAULT_ALPN_HEX || "";

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
    const { host, port } = splitHostPort(hostPort);

    const params = parseQuery(query);

    const sni = params.sni || params.host || params.tlsHost || "";
    const insecure = params.insecure === "1" || params.insecure === "true";
    const alpnHex = alpnToHex(params.alpn || "") || DEFAULT_ALPN_HEX;

    return buildQxAnytls({
      host,
      port,
      password,
      tag,
      tlsHost: sni,
      tlsVerificationFalse: insecure,
      alpnHex,
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
    const { host, port } = splitHostPort(hostPort);

    const userInfo = b64DecodeUtf8(userInfoB64);
    if (!userInfo) return line;

    const firstColon = userInfo.indexOf(":");
    if (firstColon < 0) return line;

    const method = userInfo.slice(0, firstColon);
    const password = userInfo.slice(firstColon + 1);

    // 只处理 Shadowsocks 2022 这类伪装/承载格式
    if (!/^2022-blake3-/i.test(method)) {
      return line;
    }

    const params = parseQuery(query);

    const sni = params.sni || params.host || params.tlsHost || "";
    const insecure = params.insecure === "1" || params.insecure === "true";
    const alpnHex = alpnToHex(params.alpn || "") || DEFAULT_ALPN_HEX;

    return buildQxAnytls({
      host,
      port,
      password,
      tag,
      tlsHost: sni,
      tlsVerificationFalse: insecure,
      alpnHex
    });
  } catch (e) {
    return line;
  }
}

let content = maybeBase64DecodeSubscription($resource.content || "");

let converted = content
  .split(/\r?\n/)
  .map(line => {
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
