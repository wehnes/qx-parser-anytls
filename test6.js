var FORCE_TLS_HOST = "m10.music.126.net";
var DEFAULT_ALPN_HEX = "02683208687474702f312e31";

function trim(s) {
  return String(s || "").replace(/^\s+|\s+$/g, "");
}

function hex2(n) {
  var h = n.toString(16);
  return h.length === 1 ? "0" + h : h;
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s || "");
  } catch (e) {
    return s || "";
  }
}

function normalizeB64(s) {
  s = String(s || "");
  s = s.replace(/\s+/g, "");
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  s = s.replace(/[^A-Za-z0-9+/=]/g, "");
  while (s.length % 4 !== 0) s += "=";
  return s;
}

function b64decode(s) {
  var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var str = normalizeB64(s);
  var output = "";
  var buffer = 0;
  var bits = 0;

  for (var i = 0; i < str.length; i++) {
    var c = str.charAt(i);
    if (c === "=") break;

    var val = chars.indexOf(c);
    if (val < 0) continue;

    buffer = (buffer << 6) | val;
    bits += 6;

    if (bits >= 8) {
      bits -= 8;
      output += String.fromCharCode((buffer >> bits) & 0xff);
    }
  }

  try {
    var pct = "";
    for (var j = 0; j < output.length; j++) {
      pct += "%" + hex2(output.charCodeAt(j));
    }
    return decodeURIComponent(pct);
  } catch (e) {
    return output;
  }
}

function splitHostPort(s) {
  var host = "";
  var port = "";

  s = String(s || "");

  if (s.charAt(0) === "[") {
    var end = s.indexOf("]");
    if (end >= 0) {
      host = s.substring(0, end + 1);
      port = s.substring(end + 2);
    }
  } else {
    var idx = s.lastIndexOf(":");
    if (idx >= 0) {
      host = s.substring(0, idx);
      port = s.substring(idx + 1);
    } else {
      host = s;
    }
  }

  return {
    host: host,
    port: port
  };
}

function parseQuery(qs) {
  var obj = {};
  if (!qs) return obj;

  var parts = qs.split("&");
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i];
    if (!p) continue;

    var idx = p.indexOf("=");
    if (idx < 0) {
      obj[safeDecode(p)] = "";
    } else {
      obj[safeDecode(p.substring(0, idx))] = safeDecode(p.substring(idx + 1));
    }
  }

  return obj;
}

function convertSsLine(line) {
  line = trim(line);
  if (line.indexOf("ss://") !== 0) return line;

  var body = line.substring(5);
  var tag = "";

  var hashIdx = body.indexOf("#");
  if (hashIdx >= 0) {
    tag = safeDecode(body.substring(hashIdx + 1));
    body = body.substring(0, hashIdx);
  }

  var query = "";
  var qIdx = body.indexOf("?");
  if (qIdx >= 0) {
    query = body.substring(qIdx + 1);
    body = body.substring(0, qIdx);
  }

  var atIdx = body.lastIndexOf("@");
  if (atIdx < 0) return line;

  var userInfoB64 = body.substring(0, atIdx);
  var hostPort = body.substring(atIdx + 1);

  var hp = splitHostPort(hostPort);
  var userInfo = b64decode(userInfoB64);

  var colonIdx = userInfo.indexOf(":");
  if (colonIdx < 0) return line;

  var method = userInfo.substring(0, colonIdx);
  var password = userInfo.substring(colonIdx + 1);

  if (!/^2022-blake3-/i.test(method)) {
    return line;
  }

  var params = parseQuery(query);

  var tlsHost = FORCE_TLS_HOST || params.sni || params.host || hp.host;

  var out = [];
  out.push("anytls=" + hp.host + ":" + hp.port);
  out.push("password=" + password);
  out.push("over-tls=true");
  out.push("tls-host=" + tlsHost);
  out.push("tls-verification=false");
  out.push("tls-alpn=" + DEFAULT_ALPN_HEX);
  out.push("tls-no-session-ticket=true");
  out.push("fast-open=false");
  out.push("udp-relay=true");
  out.push("tag=" + (tag || hp.host + ":" + hp.port));

  return out.join(", ");
}

function fixAnytlsLine(line) {
  line = trim(line);
  if (line.indexOf("anytls=") !== 0) return line;

  function has(key) {
    return new RegExp("(^|,\\s*)" + key + "\\s*=", "i").test(line);
  }

  var host = "";
  var m = line.match(/^anytls=([^,\s]+)/i);
  if (m) {
    var hp = splitHostPort(m[1]);
    host = hp.host;
  }

  var tlsHost = FORCE_TLS_HOST || host;

  if (!has("tls-host") && tlsHost) {
    line += ", tls-host=" + tlsHost;
  }

  if (!has("tls-alpn")) {
    line += ", tls-alpn=" + DEFAULT_ALPN_HEX;
  }

  if (!has("tls-no-session-ticket")) {
    line += ", tls-no-session-ticket=true";
  }

  if (!has("tls-verification")) {
    line += ", tls-verification=false";
  }

  if (!has("udp-relay")) {
    line += ", udp-relay=true";
  }

  return line;
}

var raw = String($resource.content || "");
var content = raw;

// 先尝试把整体订阅 Base64 解开
var decoded = b64decode(raw);
if (
  decoded.indexOf("ss://") >= 0 ||
  decoded.indexOf("anytls://") >= 0 ||
  decoded.indexOf("anytls=") >= 0
) {
  content = decoded;
}

var lines = content.split(/\r?\n/);
var result = [];

for (var i = 0; i < lines.length; i++) {
  var line = trim(lines[i]);
  if (!line) continue;

  if (line.indexOf("ss://") === 0) {
    result.push(convertSsLine(line));
  } else if (line.indexOf("anytls=") === 0) {
    result.push(fixAnytlsLine(line));
  } else {
    result.push(line);
  }
}

$done({
  content: result.join("\n")
});
