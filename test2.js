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

let raw = String($resource.content || "");
let rawTrim = raw.trim();
let decoded = b64DecodeUtf8(rawTrim);

let tag = "UNKNOWN";

if (/^ss:\/\//im.test(rawTrim)) {
  tag = "RAW_IS_SS";
} else if (/^anytls:\/\//im.test(rawTrim)) {
  tag = "RAW_IS_ANYTLS";
} else if (decoded.includes("ss://")) {
  tag = "BASE64_TO_SS";
} else if (decoded.includes("anytls://")) {
  tag = "BASE64_TO_ANYTLS";
} else {
  tag = "NO_MATCH";
}

let preview = rawTrim.slice(0, 40).replace(/[^a-zA-Z0-9]/g, "_");

$done({
  content: `anytls=example.com:443, password=test, over-tls=true, tls-host=example.com, tls-verification=false, tls-alpn=02683208687474702f312e31, tls-no-session-ticket=true, udp-relay=true, tag=${tag}_${preview}`
});
