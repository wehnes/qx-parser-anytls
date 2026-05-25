/**
 * Quantumult X Resource Parser
 * Convert anytls:// URI to Quantumult X anytls= format
 */

function safeDecode(s) {
  try {
    return decodeURIComponent(s || "");
  } catch (e) {
    return s || "";
  }
}

function maybeBase64Decode(content) {
  const text = (content || "").trim();

  // 如果本来就是明文订阅，直接返回
  if (/^(anytls|ss|ssr|vmess|vless|trojan|hysteria|http|socks|shadowsocks)=/im.test(text) ||
      /^anytls:\/\//im.test(text) ||
      text.includes("\n")) {
    return content;
  }

  // 尝试处理常见 base64 订阅
  try {
    let b64 = text.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const decoded = atob(b64);
    if (decoded && decoded.length > 0) return decoded;
  } catch (e) {}

  return content;
}

function parseQuery(qs) {
  const obj = {};
  if (!qs) return obj;

  qs.split("&").forEach(part => {
    if (!part) return;
    const idx = part.indexOf("=");
    let k, v;
    if (idx === -1) {
      k = safeDecode(part);
      v = "";
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
    const len = p.length;
    if (len <= 0 || len > 255) return;

    hex += len.toString(16).padStart(2, "0");

    for (let i = 0; i < p.length; i++) {
      hex += p.charCodeAt(i).toString(16).padStart(2, "0");
    }
  });

  return hex;
}

function convertAnytls(line) {
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

    let host = "";
    let port = "";

    // IPv6: [::1]:443
    if (hostPort.startsWith("[")) {
      const end = hostPort.indexOf("]");
      host = hostPort.slice(0, end + 1);
      port = hostPort.slice(end + 2);
    } else {
      const colon = hostPort.lastIndexOf(":");
      host = hostPort.slice(0, colon);
      port = hostPort.slice(colon + 1);
    }

    const params = parseQuery(query);

    const sni = params.sni || params.host || params.tlsHost || "";
    const insecure = params.insecure === "1" || params.insecure === "true";
    const alpnHex = alpnToHex(params.alpn || "");

    const out = [];

    out.push(`anytls=${host}:${port}`);
    out.push(`password=${password}`);
    out.push(`over-tls=true`);

    if (sni) out.push(`tls-host=${sni}`);

    if (insecure) out.push(`tls-verification=false`);

    if (alpnHex) {
      out.push(`tls-alpn=${alpnHex}`);

      // QX 官方说明：标准 TLS 配合该 ALPN 与禁用 session ticket 时会使用 iOS Safari 类指纹
      out.push(`tls-no-session-ticket=true`);
    }

    // Reality 兼容，普通 AnyTLS 没有这些字段就不会加
    if (params.pbk) out.push(`reality-base64-pubkey=${params.pbk}`);
    if (params.publicKey) out.push(`reality-base64-pubkey=${params.publicKey}`);
    if (params.sid) out.push(`reality-hex-shortid=${params.sid}`);
    if (params.shortId) out.push(`reality-hex-shortid=${params.shortId}`);

    out.push(`udp-relay=true`);

    if (tag) {
      out.push(`tag=${tag}`);
    } else {
      out.push(`tag=${host}:${port}`);
    }

    return out.join(", ");
  } catch (e) {
    return line;
  }
}

let content = maybeBase64Decode($resource.content || "");

let converted = content
  .split(/\r?\n/)
  .map(line => {
    const trimmed = line.trim();
    if (!trimmed) return line;
    if (trimmed.startsWith("anytls://")) return convertAnytls(trimmed);
    return line;
  })
  .join("\n");

$done({ content: converted });