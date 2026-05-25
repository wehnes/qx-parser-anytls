var FORCE_TLS_HOST = "m10.music.126.net";
var DEFAULT_ALPN_HEX = "02683208687474702f312e31";

function trim(s) {
  return String(s || "").replace(/^\s+|\s+$/g, "");
}

function hasParam(line, key) {
  var re = new RegExp("(^|,\\s*)" + key + "\\s*=", "i");
  return re.test(line);
}

function fixAnytlsLine(line) {
  line = trim(line);

  if (line.indexOf("anytls=") !== 0) {
    return line;
  }

  // 如果已有 tls-host，先删掉，避免重复或用错 SNI
  line = line.replace(/,\s*tls-host\s*=\s*[^,\n]+/i, "");

  // 强制插入 tls-host，放在 over-tls=true 后面
  if (/,\s*over-tls\s*=\s*true/i.test(line)) {
    line = line.replace(
      /,\s*over-tls\s*=\s*true/i,
      ", over-tls=true, tls-host=" + FORCE_TLS_HOST
    );
  } else {
    line += ", over-tls=true, tls-host=" + FORCE_TLS_HOST;
  }

  if (!hasParam(line, "tls-verification")) {
    line += ", tls-verification=false";
  }

  if (!hasParam(line, "tls-alpn")) {
    line += ", tls-alpn=" + DEFAULT_ALPN_HEX;
  }

  if (!hasParam(line, "tls-no-session-ticket")) {
    line += ", tls-no-session-ticket=true";
  }

  if (!hasParam(line, "udp-relay")) {
    line += ", udp-relay=true";
  }

  return line;
}

var content = String($resource.content || "");

var result = content
  .split(/\r?\n/)
  .map(function(line) {
    var t = trim(line);
    if (!t) return "";
    if (t.indexOf("anytls=") === 0) {
      return fixAnytlsLine(t);
    }
    return line;
  })
  .filter(function(line) {
    return line !== "";
  })
  .join("\n");

$done({
  content: result
});
