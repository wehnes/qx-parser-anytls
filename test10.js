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
      if (s.charAt(end + 1) === ":") {
        port = s.substring(end + 2);
      }
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

function parseKvLine(line) {
  var obj = {};
  var parts = String(line || "").split(",");

  for (var i = 0; i < parts.length; i++) {
    var p = trim(parts[i]);
    if (!p) continue;

    var idx = p.indexOf("=");
    if (idx < 0) continue;

    var k = trim(p.substring(0, idx));
    var v = trim(p.substring(idx + 1));

    obj[k.toLowerCase()] = v;
  }

  return obj;
}

function buildAnytlsLine(hostPort, password, tag, tlsHost, alpn) {
  var out = [];

  out.push("anytls=" + hostPort);
  out.push("password=" + password);
  out.push("over-tls=true");
  out.push("tls-host=" + (tlsHost || FORCE_TLS_HOST));
  out.push("tls-verification=false");
  out.push("tls-alpn=" + (alpn || DEFAULT_ALPN_HEX));
  out.push("tls-no-session-ticket=true");
  out.push("udp-relay=true");
  out.push("tag=" + tag);

  return out.join(", ");
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

  var userInfoRaw = body.substring(0, atIdx);
  var hostPort = body.substring(atIdx + 1);

  var userInfo = "";

  if (userInfoRaw.indexOf(":") >= 0) {
    userInfo = safeDecode(userInfoRaw);
  } else {
    userInfo = b64decode(userInfoRaw);
  }

  var colonIdx = userInfo.indexOf(":");
  if (colonIdx < 0) return line;

  var method = userInfo.substring(0, colonIdx);
  var password = userInfo.substring(colonIdx + 1);

  if (!/^2022-blake3-/i.test(method)) {
    return line;
  }

  var params = parseQuery(query);
  var tlsHost = FORCE_TLS_HOST || params.sni || params.host || "";

  return buildAnytlsLine(
    hostPort,
    password,
    tag || hostPort,
    tlsHost,
    DEFAULT_ALPN_HEX
  );
}

function fixAnytlsKvLine(line) {
  line = trim(line);
  if (line.indexOf("anytls=") !== 0) return line;

  var obj = parseKvLine(line);

  var hostPort = obj["anytls"] || "";
  var password = obj["password"] || "";
  var tag = obj["tag"] || hostPort;

  if (!hostPort || !password) {
    return line;
  }

  return buildAnytlsLine(
    hostPort,
    password,
    tag,
    FORCE_TLS_HOST,
    obj["tls-alpn"] || DEFAULT_ALPN_HEX
  );
}

function convertAnytlsUrl(line) {
  line = trim(line);
  if (line.indexOf("anytls://") !== 0) return line;

  var body = line.substring("anytls://".length);
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

  var password = "";
  var hostPort = body;

  var atIdx = body.lastIndexOf("@");
  if (atIdx >= 0) {
    password = safeDecode(body.substring(0, atIdx));
    hostPort = body.substring(atIdx + 1);
  }

  var params = parseQuery(query);

  if (!password) {
    password = params.password || params.pwd || "";
  }

  if (!hostPort || !password) {
    return line;
  }

  return buildAnytlsLine(
    hostPort,
    password,
    tag || hostPort,
    FORCE_TLS_HOST,
    params.alpn || params["tls-alpn"] || DEFAULT_ALPN_HEX
  );
}

var raw = String($resource.content || "");
var content = raw;

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
  } else if (line.indexOf("anytls://") === 0) {
    result.push(convertAnytlsUrl(line));
  } else if (line.indexOf("anytls=") === 0) {
    result.push(fixAnytlsKvLine(line));
  } else {
    result.push(line);
  }
}

$done({
  content: result.join("\n")
});
