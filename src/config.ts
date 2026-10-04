import { existsSync, mkdirSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { log } from "./log.ts";

export interface Config {
  host: string;
  port: number;
  dataDir: string;
  aliasSecret: Buffer;
  hashSecret: Buffer;
  maxBodyBytes: number;
}

const ALIAS_SECRET_FILE = "alias-secret.key";
const HASH_SECRET_FILE = "content-hash-secret.key";
const SECRET_MIN_BYTES = 32;

/**
 * Resolve one deployment secret:
 *  - an environment value may be hex (even number of hex chars) or raw UTF-8
 *    and must carry at least 16 bytes of key material;
 *  - otherwise a previously persisted secret is loaded;
 *  - otherwise a fresh 32-byte secret is generated and persisted to the data
 *    volume (single-node default; multi-replica deployments must set the
 *    environment value explicitly).
 */
async function resolveSecret(envName: string, secretFile: string): Promise<Buffer> {
  const fromEnv = process.env[envName];
  if (typeof fromEnv === "string" && fromEnv.length > 0) {
    const isHex = /^[0-9a-fA-F]{32,}$/.test(fromEnv) && fromEnv.length % 2 === 0;
    const decoded = isHex ? Buffer.from(fromEnv, "hex") : Buffer.from(fromEnv, "utf8");
    if (decoded.length < 16) {
      throw new Error(`${envName} must provide at least 16 bytes of key material`);
    }
    return decoded;
  }

  const secretPath = join(process.env.DATA_DIR ?? "/data", secretFile);
  if (existsSync(secretPath)) {
    const stored = await readFile(secretPath);
    if (stored.length < SECRET_MIN_BYTES) {
      throw new Error(`persisted secret ${secretFile} is too short`);
    }
    return stored;
  }

  const generated = randomBytes(SECRET_MIN_BYTES);
  await writeFile(secretPath, generated, { mode: 0o600 });
  log.warn("secret_generated", { env: envName, note: `set ${envName} in multi-replica deployments` });
  return generated;
}

/**
 * The two deployment secrets must be independent: deriving one from the other
 * (or sharing a value) would let the alias HMAC construction or the alias
 * outputs be reused as an oracle for the content digest. Compare in constant
 * time to avoid even a timing side channel during startup.
 */
function assertDistinctSecrets(aliasSecret: Buffer, hashSecret: Buffer): void {
  if (aliasSecret.length === hashSecret.length && timingSafeEqual(aliasSecret, hashSecret)) {
    throw new Error(
      "MANIFEST_ALIAS_SECRET and MANIFEST_HASH_SECRET must be distinct deployment secrets",
    );
  }
}

export async function loadConfig(): Promise<Config> {
  const dataDir = process.env.DATA_DIR ?? "/data";
  mkdirSync(dataDir, { recursive: true });

  const aliasSecret = await resolveSecret("MANIFEST_ALIAS_SECRET", ALIAS_SECRET_FILE);
  const hashSecret = await resolveSecret("MANIFEST_HASH_SECRET", HASH_SECRET_FILE);
  assertDistinctSecrets(aliasSecret, hashSecret);

  const portEnv = process.env.PORT ?? "8080";
  const port = Number(portEnv);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid PORT: ${portEnv}`);
  }

  const maxBodyBytes = Number(process.env.MAX_BODY_BYTES ?? "10485760");

  return {
    host: process.env.HOST ?? "0.0.0.0",
    port,
    dataDir,
    aliasSecret,
    hashSecret,
    maxBodyBytes,
  };
}
