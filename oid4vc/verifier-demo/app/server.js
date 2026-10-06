// Standalone SD-JWT VC verifier for the ACA-Py OID4VC plugin.
//
// At startup it provisions a verifier tenant on the agent: the demo SD-JWT
// issuer CA as a trust anchor, and an X.509 reader identity so requests are
// signed with x5c (client_id x509_san_dns:<agent ngrok host>). The browser
// then only talks to two routes here: create a request, and poll its result.

import express from "express";
import QRCode from "qrcode-svg";

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const API_BASE_URL = process.env.API_BASE_URL || "http://localhost:3001";
const AGENT_PUBLIC_URL = process.env.AGENT_PUBLIC_URL || "http://localhost:8082";
const READER_CA_DIR = process.env.READER_CA_DIR || path.join(__dirname, "reader-ca");
const ISSUER_CA_PEM = process.env.ISSUER_CA_PEM || path.join(__dirname, "issuer_ca.pem");
const PORT = Number(process.env.PORT || 3000);
// ngrok agent API; the UI's public URL is the tunnel named "verifier".
const TUNNEL_ENDPOINT = process.env.TUNNEL_ENDPOINT;

// The ID card from ../demo (IDCard and IDCardX5c share this vct). claim_sets are
// tried in order, so the portrait is shared when the credential has one.
const DCQL_QUERY = {
  credentials: [
    {
      id: "IDCard",
      format: "dc+sd-jwt",
      meta: { vct_values: ["ExampleIDCard"] },
      claims: [
        { id: "given_name", path: ["given_name"] },
        { id: "family_name", path: ["family_name"] },
        { id: "age_over_18", path: ["age_is_over_18"] },
        { id: "picture", path: ["picture"] },
      ],
      claim_sets: [
        ["given_name", "family_name", "age_over_18", "picture"],
        ["given_name", "family_name", "age_over_18"],
      ],
    },
  ],
};

const VP_FORMATS = {
  "dc+sd-jwt": {
    "sd-jwt_alg_values": ["ES256", "ES384"],
    "kb-jwt_alg_values": ["ES256", "ES384"],
  },
};

// Disclosed claims passed to the browser; everything else stays server side.
const SHOWN_CLAIMS = ["given_name", "family_name", "age_is_over_18"];
const IMAGE_DATA_URL = /^data:image\/(?:jpeg|png|webp|gif);base64,[A-Za-z0-9+/]+={0,2}$/;

let tenantToken = null;
let dcqlQueryId = null;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function api(method, urlPath, body) {
  const headers = { accept: "application/json" };
  if (body) headers["Content-Type"] = "application/json";
  if (tenantToken) headers.Authorization = `Bearer ${tenantToken}`;
  const res = await fetch(`${API_BASE_URL}${urlPath}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${urlPath} -> ${res.status} ${text}`);
  return text ? JSON.parse(text) : {};
}

async function waitForAgent() {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const res = await fetch(`${API_BASE_URL}/status/ready`);
      if (res.ok && (await res.json()).ready) return;
    } catch {
      // not up yet
    }
    await sleep(2000);
  }
  throw new Error(`Agent admin API not ready at ${API_BASE_URL}`);
}

// Reader certificate over the tenant's did:jwk key, signed by the demo reader
// root (../demo/reader-ca). Its DNS SAN must be the agent's public host, which
// is the response_uri host and so the x509_san_dns client_id.
function mintReaderCert(did, dnsName) {
  const rootCertPath = path.join(READER_CA_DIR, "reader_root.pem");
  const rootKeyPath = path.join(READER_CA_DIR, "reader_root.key");
  const jwk = JSON.parse(Buffer.from(did.slice("did:jwk:".length), "base64url").toString("utf-8"));
  const publicKeyPem = crypto.createPublicKey({ key: jwk, format: "jwk" })
    .export({ type: "spki", format: "pem" });

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "reader-cert-"));
  try {
    const file = (name) => path.join(workDir, name);
    fs.writeFileSync(file("pub.pem"), publicKeyPem);
    fs.writeFileSync(file("ext.cnf"), [
      "basicConstraints=critical,CA:FALSE",
      "keyUsage=critical,digitalSignature",
      "extendedKeyUsage=critical,1.0.18013.5.1.6",
      `subjectAltName=DNS:${dnsName}`,
      "subjectKeyIdentifier=hash",
      "authorityKeyIdentifier=keyid:always",
    ].join("\n") + "\n");
    // A throwaway key carries the subject; -force_pubkey swaps in the DID key,
    // so the signing key never leaves ACA-Py.
    execFileSync("openssl", [
      "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-nodes", "-keyout", file("dummy.key"),
      "-subj", `/C=CA/ST=Ontario/O=Demo SD-JWT Verifier/CN=${dnsName}`,
      "-out", file("leaf.csr"),
    ], { stdio: "pipe" });
    execFileSync("openssl", [
      "x509", "-req", "-in", file("leaf.csr"),
      "-force_pubkey", file("pub.pem"),
      "-CA", rootCertPath, "-CAkey", rootKeyPath,
      "-set_serial", `0x${crypto.randomBytes(8).toString("hex")}`,
      "-sha256", "-days", "90",
      "-extfile", file("ext.cnf"),
      "-out", file("leaf.pem"),
    ], { stdio: "pipe" });
    return fs.readFileSync(file("leaf.pem"), "utf-8") + fs.readFileSync(rootCertPath, "utf-8");
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

async function setup() {
  await waitForAgent();

  const wallet = await api("POST", "/multitenancy/wallet", {
    label: "Verifier",
    wallet_type: "askar",
  });
  tenantToken = wallet.token;
  const walletId = wallet.settings["wallet.id"];
  console.log(`Verifier tenant: ${walletId}`);

  if (fs.existsSync(ISSUER_CA_PEM)) {
    await api("POST", "/mso-mdoc/trust-anchors", {
      certificate_pem: fs.readFileSync(ISSUER_CA_PEM, "utf-8"),
      purpose: "sd_jwt_issuer",
      label: "Demo SD-JWT VC Issuer CA",
    });
    console.log("Trusted SD-JWT issuer CA registered");
  } else {
    console.warn(`No issuer CA at ${ISSUER_CA_PEM}: x5c-signed credentials will fail verification`);
  }

  const { did } = await api("POST", "/did/jwk/create", { key_type: "p256" });
  const metadataUrl = `${AGENT_PUBLIC_URL}/.well-known/openid-credential-issuer/tenant/${walletId}`;
  const { credential_issuer } = await (await fetch(metadataUrl)).json();
  const dnsName = new URL(credential_issuer).hostname;
  const identity = await api("POST", "/oid4vp/x509-identity", {
    cert_chain_pem: mintReaderCert(did, dnsName),
    verification_method: `${did}#0`,
    client_id: dnsName,
  });
  console.log(`Reader identity: client_id=x509_san_dns:${identity.client_id}`);

  ({ dcql_query_id: dcqlQueryId } = await api("POST", "/oid4vp/dcql/queries", DCQL_QUERY));
}

async function publicUiUrl() {
  if (!TUNNEL_ENDPOINT) return null;
  for (let attempt = 0; attempt < 15; attempt++) {
    try {
      const { tunnels } = await (await fetch(`${TUNNEL_ENDPOINT}/api/tunnels`)).json();
      const tunnel = tunnels.find((t) => t.name === "verifier" && t.public_url);
      if (tunnel) return tunnel.public_url;
    } catch {
      // ngrok not answering yet
    }
    await sleep(2000);
  }
  return null;
}

function qrSvg(content) {
  const svg = new QRCode({
    content,
    padding: 0,
    width: 256,
    height: 256,
    color: "#111827",
    background: "#ffffff",
    ecl: "M",
    join: true,
    container: "svg-viewbox",
  }).svg();
  return svg.substring(svg.indexOf("<svg"));
}

function summarize(record) {
  const result = { state: record.state };
  if (record.state === "presentation-valid") {
    const credential = Object.values(record.matched_credentials || {})[0] || {};
    result.claims = Object.fromEntries(
      SHOWN_CLAIMS.filter((name) => credential[name] !== undefined)
        .map((name) => [name, credential[name]]),
    );
    if (typeof credential.picture === "string" && IMAGE_DATA_URL.test(credential.picture)) {
      result.picture = credential.picture;
    }
    result.credential = {
      type: credential.vct,
      issuer: credential.iss,
      issued_at: credential.iat,
      expires_at: credential.exp,
    };
  } else if (record.state === "presentation-invalid") {
    result.errors = record.errors || [];
  }
  return result;
}

const app = express();
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/verify", async (req, res) => {
  if (!dcqlQueryId) {
    return res.status(503).json({ error: "The verifier is still starting. Try again shortly." });
  }
  try {
    const { request_uri, presentation } = await api("POST", "/oid4vp/request", {
      dcql_query_id: dcqlQueryId,
      vp_formats: VP_FORMATS,
    });
    res.json({ id: presentation.presentation_id, request_uri, qr: qrSvg(request_uri) });
  } catch (err) {
    console.error(err.message);
    res.status(502).json({ error: "Could not create a presentation request." });
  }
});

app.get("/api/verify/:id", async (req, res) => {
  if (!/^[0-9a-f-]{36}$/i.test(req.params.id)) {
    return res.status(400).json({ error: "Invalid request id." });
  }
  try {
    res.json(summarize(await api("GET", `/oid4vp/presentation/${req.params.id}`)));
  } catch (err) {
    console.error(err.message);
    res.status(502).json({ error: "Could not read the presentation." });
  }
});

app.listen(PORT, () => console.log(`Verifier UI on port ${PORT}`));

try {
  await setup();
  const url = await publicUiUrl();
  console.log(url ? `Verifier ready: open ${url}` : `Verifier ready on http://localhost:${PORT}`);
} catch (err) {
  console.error(`Setup failed: ${err.message}`);
  process.exit(1);
}
