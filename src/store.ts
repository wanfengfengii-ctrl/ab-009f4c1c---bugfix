import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { readdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { SharedManifest, ValidationIssue } from "./types.ts";
import { CorruptManifestError } from "./types.ts";
import { validatePersistedManifest } from "./sharedValidation.ts";
import { MIGRATED_CONTENT_KEY_ID, neutralizedLegacyContentHash } from "./contentKey.ts";
import { log } from "./log.ts";

/**
 * Persistent manifest store.
 *
 * Only alias-only {@link SharedManifest} documents are ever written to disk;
 * raw identifiers exist solely in the short-lived request handling scope.
 * Files are named by SHA-256(batchId) so storage paths contain no client
 * supplied identifier text, and writes are atomic (temp file + rename).
 *
 * Recovery is fail-closed: a data volume may have been restored from a
 * backup, migrated from an older version or logically corrupted, so every
 * persisted entry is re-validated against the full current shared-manifest
 * contract (structure, alias/hash/timestamp formats, scalar measurements,
 * record-alias uniqueness, reference closure and the file-name <-> batchId
 * binding) before it is trusted. Any corrupt entry is reported via
 * diagnostics that contain only the hashed file name, rule codes and JSON
 * paths — never file contents — and aborts startup. A corrupt entry is
 * therefore never served by GET and never treated as absent, so a batchId
 * with a corrupt entry cannot be silently overwritten either.
 */

export type CreateOutcome =
  | { status: "created"; manifest: SharedManifest }
  | { status: "replayed"; manifest: SharedManifest }
  | { status: "conflict" };

/**
 * Startup aborts when one or more persisted entries fail recovery
 * validation. Carries only the (hashed) file names, never entry contents.
 */
export class CorruptStoreError extends Error {
  readonly files: string[];

  constructor(files: string[]) {
    super(
      `refusing to start: ${files.length} persisted manifest(s) failed recovery validation: ` +
        files.join(", "),
    );
    this.name = "CorruptStoreError";
    this.files = files;
  }
}

export class ManifestStore {
  private readonly manifests = new Map<string, SharedManifest>();
  /** Serializes concurrent creates targeting the same batchId. */
  private readonly locks = new Map<string, Promise<unknown>>();

  private readonly dataDir: string;
  /**
   * Deployment-only key for content hashes. Required for neutralizing
   * pre-upgrade unkeyed hashes on recovery load.
   */
  private readonly contentKey: Buffer;

  constructor(dataDir: string, contentKey: Buffer) {
    if (!Buffer.isBuffer(contentKey) || contentKey.length < 16) {
      throw new Error("content key must be a Buffer of at least 16 bytes");
    }
    this.dataDir = dataDir;
    this.contentKey = contentKey;
    mkdirSync(dataDir, { recursive: true });
  }

  private fileName(batchId: string): string {
    return createHash("sha256").update(batchId, "utf8").digest("hex") + ".json";
  }

  /** Atomically persist a shared manifest document (temp file + rename). */
  private async persist(manifest: SharedManifest): Promise<void> {
    const target = join(this.dataDir, this.fileName(manifest.batchId));
    const tmp = `${target}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, JSON.stringify(manifest), { mode: 0o600 });
    await rename(tmp, target);
  }

  async load(): Promise<void> {
    const entries = await readdir(this.dataDir);
    const corrupt: Array<{ file: string; issues: ValidationIssue[] }> = [];
    /** Valid pre-upgrade entries awaiting hash neutralization. */
    const pendingMigration: Array<{ file: string; manifest: SharedManifest }> = [];
    let count = 0;
    for (const entry of entries.sort()) {
      if (!entry.endsWith(".json")) continue;
      const result = await this.inspectEntry(entry);
      if (result.kind === "corrupt") {
        corrupt.push({ file: entry, issues: result.issues });
      } else if (result.kind === "legacy") {
        pendingMigration.push({ file: entry, manifest: result.manifest });
      } else {
        count++;
      }
    }
    // Report every corrupt entry before aborting so a single restart cycle
    // surfaces all of them. The diagnostics contain only hashed file names,
    // rule codes and JSON paths — corrupt content itself is never logged.
    // No file is migrated until every entry has been validated, so a corrupt
    // volume always fails closed without partial rewrites.
    for (const entry of corrupt) {
      log.error("store_corrupt_entry", {
        file: entry.file,
        issues: JSON.stringify(entry.issues),
      });
    }
    if (corrupt.length > 0) {
      throw new CorruptStoreError(corrupt.map((entry) => entry.file));
    }

    // Neutralize pre-upgrade manifests: their unkeyed contentHash would let
    // anyone with the response confirm low-entropy identifier guesses even
    // after the upgrade. Rewrite to a keyed hash and stamp the marker,
    // atomically, BEFORE the entry is admitted for serving. Idempotent: a
    // manifest already stamped on an earlier restart is current-contract and
    // never reaches here.
    for (const { file, manifest } of pendingMigration) {
      const neutralized: SharedManifest = {
        ...manifest,
        contentHash: neutralizedLegacyContentHash(manifest.contentHash, this.contentKey),
        contentKeyId: MIGRATED_CONTENT_KEY_ID,
      };
      await this.persist(neutralized);
      this.manifests.set(neutralized.batchId, neutralized);
      count++;
      log.info("store_legacy_hash_neutralized", { file });
    }

    log.info("store_loaded", { manifests: count, migrated: pendingMigration.length });
  }

  /**
   * Validate one persisted entry.
   *  - "current": fully contract-compliant document, admitted as-is
   *  - "legacy": valid pre-upgrade document lacking contentKeyId; its unkeyed
   *    hash must be neutralized before serving
   *  - "corrupt": contract violations; the entry is never admitted and the
   *    whole load aborts
   */
  private async inspectEntry(
    entry: string,
  ): Promise<
    | { kind: "current"; manifest: SharedManifest }
    | { kind: "legacy"; manifest: SharedManifest }
    | { kind: "corrupt"; issues: ValidationIssue[] }
  > {
    let raw: string;
    try {
      raw = await readFile(join(this.dataDir, entry), "utf8");
    } catch {
      return {
        kind: "corrupt",
        issues: [
          { code: "unreadable_entry", path: "$", message: "persisted manifest could not be read" },
        ],
      };
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return {
        kind: "corrupt",
        issues: [
          { code: "invalid_json", path: "$", message: "persisted manifest is not valid JSON" },
        ],
      };
    }

    let result: { manifest: SharedManifest; legacyUnkeyed: boolean };
    try {
      result = validatePersistedManifest(parsed, true);
    } catch (err) {
      if (err instanceof CorruptManifestError) return { kind: "corrupt", issues: err.issues };
      throw err;
    }

    // The storage key is part of the contract: the file name must be the
    // SHA-256 of the batchId it claims to hold.
    if (entry !== this.fileName(result.manifest.batchId)) {
      return {
        kind: "corrupt",
        issues: [
          {
            code: "batch_id_file_mismatch",
            path: "$.batchId",
            message: "batchId does not match the persisted file name binding",
          },
        ],
      };
    }

    if (result.legacyUnkeyed) {
      return { kind: "legacy", manifest: result.manifest };
    }
    this.manifests.set(result.manifest.batchId, result.manifest);
    return { kind: "current", manifest: result.manifest };
  }

  get(batchId: string): SharedManifest | undefined {
    return this.manifests.get(batchId);
  }

  /**
   * Idempotent create.
   *  - first submission for the batchId: persist and return "created"
   *  - identical business content (same content hash): return "replayed"
   *  - different content for the same batchId: return "conflict" (HTTP 409)
   */
  create(batchId: string, contentDigest: string, manifest: SharedManifest): Promise<CreateOutcome> {
    const prior = this.locks.get(batchId) ?? Promise.resolve();
    const result = prior.then(() => this.createInner(batchId, contentDigest, manifest));
    this.locks.set(
      batchId,
      result.catch(() => undefined),
    );
    return result;
  }

  private async createInner(
    batchId: string,
    contentDigest: string,
    manifest: SharedManifest,
  ): Promise<CreateOutcome> {
    const existing = this.manifests.get(batchId);
    if (existing !== undefined) {
      // A migrated pre-upgrade entry carries a neutralized hash derived only
      // from the old digest (the original identifiers are not recoverable),
      // so equality against new content cannot be established; its key
      // fingerprint differs as well. Every re-submission therefore answers
      // with the existing 409 rather than risking an unknowable overwrite.
      return existing.contentHash === contentDigest &&
        existing.contentKeyId === manifest.contentKeyId
        ? { status: "replayed", manifest: existing }
        : { status: "conflict" };
    }

    await this.persist(manifest);
    this.manifests.set(batchId, manifest);
    return { status: "created", manifest };
  }
}
