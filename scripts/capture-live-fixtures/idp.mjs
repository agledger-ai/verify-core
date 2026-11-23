/**
 * A minimal OIDC issuer for fixture capture: a discovery document, a JWKS
 * holding one Ed25519 key, and in-process token minting. It exists so a scratch
 * Server can be driven through the cert exchange and the delegated
 * on-behalf-of path without a real identity provider. Never expose it beyond
 * the capture run: it signs whatever it is asked to.
 */
import { createServer } from 'node:http';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';

const b64url = (buf) => Buffer.from(buf).toString('base64url');

/**
 * Start an issuer.
 *
 * @param {object} opts
 * @param {string} opts.issuer   The `iss` it signs and the URL the Server reaches it at.
 * @param {string} opts.listen   `host:port` to bind (the address the issuer host name resolves to).
 * @param {string} opts.kid      Key id published in the JWKS and the token header.
 * @returns {Promise<{ issuer: string, jwksUri: string, mint: (claims: object) => string, close: () => Promise<void> }>}
 */
export async function startIssuer({ issuer, listen, kid }) {
  const base = issuer.replace(/\/+$/, '');
  const jwksUri = `${base}/.well-known/jwks.json`;
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const { x } = publicKey.export({ format: 'jwk' });
  const jwks = { keys: [{ kty: 'OKP', crv: 'Ed25519', x, kid, alg: 'EdDSA', use: 'sig' }] };
  const discovery = {
    issuer: base,
    jwks_uri: jwksUri,
    id_token_signing_alg_values_supported: ['EdDSA'],
    subject_types_supported: ['public'],
    response_types_supported: ['id_token'],
  };

  const server = createServer((req, res) => {
    const path = new URL(req.url ?? '/', base).pathname;
    const body =
      path === '/.well-known/openid-configuration' ? discovery
        : path === '/.well-known/jwks.json' ? jwks
          : null;
    res.writeHead(body ? 200 : 404, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body ?? { error: 'not_found' }));
  });
  const sep = listen.lastIndexOf(':');
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(Number(listen.slice(sep + 1)), listen.slice(0, sep), resolve);
  });

  /** Sign a compact JWS over `claims`, filling iss, iat, exp and jti unless given. */
  function mint(claims) {
    const now = Math.floor(Date.now() / 1000);
    const payload = { iss: base, iat: now, exp: now + 600, jti: randomUUID(), ...claims };
    const header = { alg: 'EdDSA', kid, typ: 'JWT' };
    const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
    return `${input}.${b64url(sign(null, Buffer.from(input), privateKey))}`;
  }

  return {
    issuer: base,
    jwksUri,
    mint,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
