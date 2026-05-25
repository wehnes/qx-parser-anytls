let raw = String($resource.content || "");
let t = raw.trim();

let tag = "UNKNOWN";

if (/anytls=/i.test(t)) {
  tag = "RAW_HAS_ANYTLS_EQUAL";
} else if (/shadowsocks=/i.test(t)) {
  tag = "RAW_HAS_SHADOWSOCKS_EQUAL";
} else if (/ss:\/\//i.test(t)) {
  tag = "RAW_HAS_SS_URI";
} else if (/anytls:\/\//i.test(t)) {
  tag = "RAW_HAS_ANYTLS_URI";
} else {
  tag = "RAW_UNKNOWN";
}

let preview = t
  .slice(0, 80)
  .replace(/[^a-zA-Z0-9=_:.,/-]/g, "_");

$done({
  content: `anytls=example.com:443, password=test, over-tls=true, tls-host=example.com, tls-verification=false, tls-alpn=02683208687474702f312e31, tls-no-session-ticket=true, udp-relay=true, tag=${tag}_${preview}`
});
