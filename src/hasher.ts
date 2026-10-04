import { createHash, createHmac } from "node:crypto";

/**
 * Deployment-scoped digest of manifest business content.
 *
 * The pre-upgrade digest was a plain SHA-256 of the canonical content and was
 * returned in POST/GET responses. Anyone receiving it could independently hash
 * candidate business contents and compare, turning low-entropy patient numbers,
 * accession numbers and record ids into a guess-verification oracle (even for a
 * single record with empty measurements).
 *
 * The current form is a keyed digest:
 *
 *   contentHash = "hmac256-" + HMAC-SHA256(hashSecret, SHA256_hex(canonical))
 *
 * Without the deployment hash secret a response recipient cannot compute a
 * comparable value for any candidate content, so correct and incorrect guesses
 * are indistinguishable.
 *
 * The HMAC is intentionally taken over the *plain digest hex* rather than over
 * the canonical text: the value persisted for a pre-upgrade manifest is exactly
 * that plain digest, so wrapping it during migration yields the identical value
 * a same-content retry computes under the new rule. Idempotent replay therefore
 * survives the upgrade even though the original identifiers (and thus the
 * canonical text) are not recoverable from an alias-only stored document.
 */

export const CONTENT_HASH_PREFIX = "hmac256-";

const HEX_64 = /^[0-9a-f]{64}$/;
const CURRENT_HASH_PATTERN = new RegExp(`^${CONTENT_HASH_PREFIX}[0-9a-f]{64}$`);

export class ContentHasher {
  private readonly secret: Buffer;

  constructor(secret: Buffer) {
    if (!Buffer.isBuffer(secret) || secret.length < 16) {
      throw new Error("content hash secret must be a Buffer of at least 16 bytes");
    }
    this.secret = secret;
  }

  /** Current keyed digest for canonical business content. */
  contentHash(canonical: string): string {
    const plain = createHash("sha256").update(canonical, "utf8").digest("hex");
    return this.keyOverPlainDigest(plain);
  }

  /**
   * Wrap a pre-upgrade plain SHA-256 digest hex into the current keyed form.
   * By construction this equals {@link contentHash} for the content the plain
   * digest was computed from.
   */
  migrateLegacyHash(legacyHex: string): string {
    return this.keyOverPlainDigest(legacyHex);
  }

  private keyOverPlainDigest(plainHex: string): string {
    const mac = createHmac("sha256", this.secret).update(plainHex, "utf8").digest("hex");
    return `${CONTENT_HASH_PREFIX}${mac}`;
  }

  /** A bare 64-hex digest: the pre-upgrade, publicly verifiable form. */
  static isLegacyHash(value: unknown): value is string {
    return typeof value === "string" && HEX_64.test(value);
  }

  /** The current prefixed keyed form. */
  static isCurrentHash(value: unknown): value is string {
    return typeof value === "string" && CURRENT_HASH_PATTERN.test(value);
  }
}
