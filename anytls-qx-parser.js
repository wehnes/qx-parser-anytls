/**
 * Quantumult X Resource Parser - AnyTLS SS2022 diagnostic version
 *
 * It decodes:
 *   Base64 subscription
 *     -> ss://base64(2022-blake3-aes-256-gcm:xxx:yyy)@host:port#tag
 *
 * Then generates 3 QX anytls nodes:
 *   [PASS] password=xxx:yyy
 *   [FULL] password=2022-blake3-aes-256-gcm:xxx:yyy
 *   [B64]  password=original userinfo base64
 */

const DEFAULT_TLS_HOST = "m10.music.126.net";
// 如果你确定必须伪装 SNI，例如：
// const DEFAULT_TLS_HOST = "m10.music.126.net";

const DEFAULT_TLS_VERIFICATION_FALSE = true;
const DEFAULT_ALPN_HEX = "02683208687474702f312e31";

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

function b64DecodeUtf8(s) {
  try {
    const bin = atob(b64Normalize(s));
    try {
      return decodeURIComponent(
        bin.split("").map(function (c) {
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

function decodeSubscriptionIfNeeded(content) {
  const raw = String(content || "");
  const trimmed = raw.trim();

  if (
    /^ss:\/\//im.test(trimmed) ||
    /^anytls:\/\//im.test(trimmed) ||
    /^anytls=/im.test(trimmed) ||
    /^shadowsocks=/im.test(trimmed)
  ) {
    return raw;
  }

  const compact = trimmed.replace(/\s+/g, "");

  if (/^[A-Za-z0-9+/_=-]+$/.test(compact) && compact.length > 16) {
    const decoded = b64DecodeUtf8(compact);

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
    if (idx === -1) {
      obj[safeDecode(part)] = "";
    } else {
      obj[safeDecode(part.slice(0, idx))] = safeDecode(part.slice(idx + 1));
    }
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

function buildQxAnytls(host, port, password, tag, tlsHost, alpnHex, insecure) {
  const out = [];

  out.push(`anytls=${host}:${port}`);
  out.push(`password=${password}`);
  out.push("over-tls=true");

  const finalTlsHost = tlsHost || DEFAULT_TLS_HOST || host;
  if (finalTlsHost) {
    out.push(`tls-host=${finalTlsHost}`);
  }

  if (insecure || DEFAULT_TLS_VERIFICATION_FALSE) {
    out.push("tls-verification=false");
  }

  const finalAlpn = alpnHex || DEFAULT_ALPN_HEX;
  if (finalAlpn) {
    out.push(`tls-alpn=${finalAlpn}`);
    out.push("tls-no-session-ticket=true");
  }

  out.push("udp-relay=true");
  out.push(`tag=${tag}`);

  return out.join(", ");
}

function convertSs2022ToThreeAnytls(line) {
  const raw = line.trim();
  if (!raw.startsWith("ss://")) return line;

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

    const userInfoB64Raw = main.slice(0, atIndex);
    const userInfoB64Normalized = b64Normalize(userInfoB64Raw);
    const hostPort = main.slice(atIndex + 1);

    const hp = splitHostPort(hostPort);
    const userInfo = b64DecodeUtf8(userInfoB64Raw);

    if (!userInfo) return line;

    const firstColon = userInfo.indexOf(":");
    if (firstColon < 0) return line;

    const method = userInfo.slice(0, firstColon);
    const passwordOnly = userInfo.slice(firstColon + 1);
    const passwordFull = userInfo;
    const passwordB64 = userInfoB64Normalized;

    if (!/^2022-blake3-/i.test(method)) {
      return line;
    }

    const params = parseQuery(query);
    const sni = params.sni || params.host || params.tlsHost || "";
    const insecure = params.insecure === "1" || params.insecure === "true";
    const alpnHex = alpnToHex(params.alpn || "") || DEFAULT_ALPN_HEX;

    const baseTag = tag || `${hp.host}:${hp.port}`;

    const nodes = [];

    nodes.push(buildQxAnytls(
      hp.host,
      hp.port,
      passwordOnly,
      `${baseTag} [PASS]`,
      sni,
      alpnHex,
      insecure
    ));

    nodes.push(buildQxAnytls(
      hp.host,
      hp.port,
      passwordFull,
      `${baseTag} [FULL]`,
      sni,
      alpnHex,
      insecure
    ));

    nodes.push(buildQxAnytls(
      hp.host,
      hp.port,
      passwordB64,
      `${baseTag} [B64]`,
      sni,
      alpnHex,
      insecure
    ));

    return nodes.join("\n");
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

    return buildQxAnytls(
      hp.host,
      hp.port,
      password,
      tag || `${hp.host}:${hp.port}`,
      sni,
      alpnHex,
      insecure
    );
  } catch (e) {
    return line;
  }
}

let content = decodeSubscriptionIfNeeded($resource.content || "");

let converted = content
  .split(/\r?\n/)
  .map(function (line) {
    const trimmed = line.trim();

    if (!trimmed) return "";

    if (trimmed.startsWith("ss://")) {
      return convertSs2022ToThreeAnytls(trimmed);
    }

    if (trimmed.startsWith("anytls://")) {
      return convertAnytlsUri(trimmed);
    }

    return line;
  })
  .filter(Boolean)
  .join("\n");

$done({ content: converted });
