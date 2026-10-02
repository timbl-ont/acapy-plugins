#!/usr/bin/env node
// Checks the issuer signature of an SD-JWT VC that carries an x5c header:
// ES256 signature against the leaf certificate's key, chain links, anchor in
// issuer_ca.pem, and `iss` matching a SAN URI of the leaf.
//
// Usage:
//   node verify-sdjwt-x5c.mjs '<sd-jwt>'
//   podman logs demo_issuer_1 2>&1 | node verify-sdjwt-x5c.mjs   # last issued
import crypto from "node:crypto";
import fs from "node:fs";

const input = process.argv[2] ?? fs.readFileSync(0, "utf8");
const logged = [...input.matchAll(/SD JWT VC CREDENTIAL: (\S+)/g)];
const sdJwt = (logged.length ? logged.at(-1)[1] : input).trim();
const [h, p, s] = sdJwt.split("~")[0].split(".");
const header = JSON.parse(Buffer.from(h, "base64url"));
const payload = JSON.parse(Buffer.from(p, "base64url"));

console.log("header:", JSON.stringify({ ...header, x5c: header.x5c?.map((c) => `${c.slice(0, 24)}…`) }));
console.log("iss:", payload.iss, " vct:", payload.vct);
if (!Array.isArray(header.x5c) || !header.x5c.length) {
  console.error("FAIL: no x5c header");
  process.exit(1);
}

const chain = header.x5c.map((c) => new crypto.X509Certificate(Buffer.from(c, "base64")));
const leaf = chain[0];
console.log("leaf subject:", leaf.subject.replace(/\n/g, ", "));
console.log("leaf SAN:", leaf.subjectAltName);

const ca = new crypto.X509Certificate(fs.readFileSync(new URL("issuer_ca.pem", import.meta.url)));
const top = chain.at(-1);
const now = new Date();
const checks = {
  "alg is ES256": header.alg === "ES256",
  "signature verifies with leaf key": crypto.verify(
    "sha256", Buffer.from(`${h}.${p}`),
    { key: leaf.publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"),
  ),
  "chain links verify": chain.slice(0, -1).every((c, i) => c.checkIssued(chain[i + 1]) && c.verify(chain[i + 1].publicKey)),
  "chain anchors in issuer_ca.pem": top.fingerprint256 === ca.fingerprint256 || (top.checkIssued(ca) && top.verify(ca.publicKey)),
  "leaf currently valid": new Date(leaf.validFrom) <= now && now <= new Date(leaf.validTo),
  "iss matches a SAN URI": (leaf.subjectAltName ?? "").split(", ").includes(`URI:${payload.iss}`),
};
for (const [name, ok] of Object.entries(checks)) console.log(`${ok ? "PASS" : "FAIL"}: ${name}`);
process.exit(Object.values(checks).every(Boolean) ? 0 : 1);
