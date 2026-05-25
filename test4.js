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

function safePreview(s) {
  return String(s || "")
    .slice(0, 120)
    .replace(/[A-Za-z0-9+/=_-]{16,}/g, "BASE64LIKE")
    .replace(/password\s*=\s*[^,\n]+/gi, "password=MASKED")
    .replace(/passwd\s*=\s*[^,\n]+/gi, "passwd=MASKED")
    .replace(/pwd\s*=\s*[^,\n]+/gi, "pwd=MASKED")
    .replace(/ss:\/\/[^#\s]+/gi, "ss://MASKED")
    .replace(/anytls:\/\/[^#\s]+/gi, "anytls://MASKED")
    .replace(/[^a-zA-Z0-9\u4e00-\u9fa5:=,./?#&\[\]_-]/g, "_");
}

let raw = String($resource.content || "");
let rawTrim = raw.trim();

let decoded1 = b64DecodeUtf8(rawTrim);
let decoded2 = "";

try {
  decoded2 = decodeURIComponent(rawTrim);
} catch (e) {
  decoded2 = "";
}

let tag = "RAW_UNKNOWN";

if (/ss:\/\//i.test(rawTrim)) {
  tag = "RAW_HAS_SS_URI";
} else if (/anytls:\/\//i.test(rawTrim)) {
  tag = "RAW_HAS_ANYTLS_URI";
} else if (/anytls=/i.test(rawTrim)) {
  tag = "RAW_HAS_ANYTLS_EQUAL";
} else if (/shadowsocks=/i.test(rawTrim)) {
  tag = "RAW_HAS_SHADOWSOCKS_EQUAL";
} else if (/proxies:/i.test(rawTrim) || /proxy-groups:/i.test(rawTrim)) {
  tag = "RAW_IS_CLASH_YAML";
} else if (/ss:\/\//i.test(decoded1)) {
  tag = "B64_TO_SS_URI";
} else if (/anytls:\/\//i.test(decoded1)) {
  tag = "B64_TO_ANYTLS_URI";
} else if (/anytls=/i.test(decoded1)) {
  tag = "B64_TO_ANYTLS_EQUAL";
} else if (/proxies:/i.test(decoded1) || /proxy-groups:/i.test(decoded1)) {
  tag = "B64_TO_CLASH_YAML";
} else if (/ss:\/\//i.test(decoded2)) {
  tag = "URLDECODE_TO_SS_URI";
} else if (/anytls:\/\//i.test(decoded2)) {
  tag = "URLDECODE_TO_ANYTLS_URI";
}

let rawPreview = safePreview(rawTrim);
let b64Preview = safePreview(decoded1);
let urlPreview = safePreview(decoded2);

let finalTag =
  tag +
  "_LEN" + rawTrim.length +
  "_RAW_" + rawPreview +
  "_B64_" + b64Preview +
  "_URL_" + urlPreview;

$done({
  content: `anytls=example.com:443, password=test, over-tls=true, tls-host=example.com, tls-verification=false, tls-alpn=02683208687474702f312e31, tls-no-session-ticket=true, udp-relay=true, tag=${finalTag}`
});
