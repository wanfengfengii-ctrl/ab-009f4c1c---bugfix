import { createHash, createHmac } from "node:crypto";
import { canonicalize } from "./canonical.ts";
import type { InputBatch } from "./types.ts";

/**
 * Keyed content hashing.
 *
 * The content hash exposed in POST/GET responses must NOT be an ordinary
 * digest of the business content: the canonical form contains the raw
 * patientId / accessionId / recordId values, so an unkeyed SHA-256 would let
 * any recipient confirm low-entropy guesses for those identifiers by hashing
 * candidate submissions locally ("hash oracle").
 *
 * Instead the exposed hash is HMAC-SHA256 under a deployment-only content key
 * derived from the persisted alias secret:
 *  - deterministic for one deployment -> identical-content retries still
 *    compare equal, different content still compares different (the HMAC is a
 *    PRF, so it preserves every equality/conflict property the unkeyed digest
 *    provided internally);
 *  - unforgeable by recipients -> without the key, hashes for candidate
 *    original values are indistinguishable and the plain SHA-256 of any guess
 *    never matches;
 *  - domain separated -> the label embedded in the HMAC message makes these
 *    digests unavailable as oracles for the alias HMACs and vice versa.
 *
 * Pre-v2 manifests persisted with an unkeyed SHA-256 keep offering the oracle
 * after an upgrade unless rewritten. On recovery load the store neutralizes
 * them with {@link neutralizedLegacyContentHash}: a KEYED transform of the old
 * digest only (never of the original content, which is not recoverable from
 * the alias-only document). A plain hash of that transform would itself be an
 * oracle, which is why neutralization is also HMAC-keyed.
 */

const SEPARATOR = String.fromCharCode(0);

/** Label inside the HMAC message for the content key derived from the alias key. */
const CONTENT_KEY_DERIVATION_LABEL = "manifest-content-hash-key-v2";
/** Label inside the HMAC message for the exposed per-content hash. */
const CONTENT_HASH_LABEL = "manifest-content-hash-v2";
/** Label inside the HMAC message for one-time neutralization of legacy hashes. */
const LEGACY_NEUTRALIZATION_LABEL = "manifest-content-hash-v1-neutralization-v2";

/** Version prefix for fingerprints produced by {@link contentKeyId}. */
const KEY_ID_VERSION = "v2";
const KEY_ID_FINGERPRINT_HEX = 16; // 64 bits

/**
 * Stored in SharedManifest.contentKeyId for documents whose pre-v2 unkeyed
 * hash was neutralized on recovery load. Such documents stay queryable but
 * can no longer participate in content-equality comparisons (the original
 * identifiers needed to recompute a keyed hash are not recoverable), so a
 * re-submission is answered with the existing 409 conflict.
 */
export const MIGRATED_CONTENT_KEY_ID = "v1-neutralized";

/** Version tag / fingerprint charset: conservative, same shape as a batchId. */
export const CONTENT_KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * Derive the 256-bit content-hash key from the deployment alias secret.
 * Derivation (rather than key reuse) keeps the content-hash and alias HMAC
 * domains cryptographically separated.
 */
export function deriveContentKey(aliasSecret: Buffer): Buffer {
  if (!Buffer.isBuffer(aliasSecret) || aliasSecret.length < 16) {
    throw new Error("alias secret must be a Buffer of at least 16 bytes");
  }
  return createHmac("sha256", aliasSecret).update(CONTENT_KEY_DERIVATION_LABEL, "utf8").digest();
}

/**
 * Stable, non-revealing fingerprint of the content key. It lets recipients
 * tell which deployment key produced a hash without disclosing the key:
 * it is a hash of the key, so it cannot be used to forge content hashes.
 */
export function contentKeyId(key: Buffer): string {
  const fingerprint = createHash("sha256").update(key).digest("hex").slice(0, KEY_ID_FINGERPRINT_HEX);
  return `${KEY_ID_VERSION}-${fingerprint}`;
}

/**
 * The hash exposed to clients in responses and persisted for
 * idempotency/conflict comparison. Requires the deployment content key.
 */
export function publicContentHash(batch: InputBatch, key: Buffer): string {
  return createHmac("sha256", key)
    .update(CONTENT_HASH_LABEL + SEPARATOR, "utf8")
    .update(canonicalize(batch), "utf8")
    .digest("hex");
}

/**
 * Replace a pre-v2 unkeyed content hash with a keyed value that no longer
 * confirms candidate originals. Commits only to the old digest (the original
 * content is unavailable during recovery), and is keyed so that nobody can
 * reproduce the new value from a guessed original without the deployment key.
 * Deterministic, so repeated restarts neutralize exactly once and stably.
 */
export function neutralizedLegacyContentHash(oldHash: string, key: Buffer): string {
  return createHmac("sha256", key)
    .update(LEGACY_NEUTRALIZATION_LABEL + SEPARATOR, "utf8")
    .update(oldHash, "utf8")
    .digest("hex");
}
