import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { readdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { SharedManifest, ValidationIssue } from "./types.ts";
import { CorruptManifestError } from "./types.ts";
import { validateSharedManifest } from "./sharedValidation.ts";
import { ContentHasher } from "./hasher.ts";
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
  private readonly hasher: ContentHasher;

  constructor(dataDir: string, hasher: ContentHasher) {
    this.dataDir = dataDir;
    this.hasher = hasher;
    mkdirSync(dataDir, { recursive: true });
  }

  private fileName(batchId: string): string {
    return createHash("sha256").update(batchId, "utf8").digest("hex") + ".json";
  }

  /**
   * One-time migration of pre-upgrade manifests.
   *
   * Before the keyed content digest was introduced, persisted documents stored
   * a bare SHA-256 of the business content. Such a digest keeps offering the
   * guess-verification oracle even after an upgrade, since GET serves the
   * stored value and the digest is publicly recomputable. Every legacy hash is
   * therefore wrapped into the current keyed form (hmac256- HMAC over the bare
   * digest) and atomically rewritten before any entry is admitted or served.
   *
   * Wrapping preserves idempotency: a same-content retry under the new rule
   * hashes the same canonical text to the same bare digest and keys it with the
   * same secret, so it compares equal to the migrated value.
   *
   * Entries that fail to parse or do not carry a bare 64-hex hash are left
   * untouched; the regular fail-closed load then validates (and, if needed,
   * rejects) them. Diagnostics stay identifier-free: only the migrated count
   * is logged.
   */
  private async migrateLegacyHashes(): Promise<void> {
    let migrated = 0;
    const entries = await readdir(this.dataDir);
    for (const entry of entries) {
      if (!entry.endsWith(".json")) continue;
      const target = join(this.dataDir, entry);

      let raw: string;
      try {
        raw = await readFile(target, "utf8");
      } catch {
        continue; // inspectEntry reports unreadable entries during load
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        continue; // inspectEntry reports malformed JSON during load
      }
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) continue;

      const document = parsed as { contentHash?: unknown };
      if (!ContentHasher.isLegacyHash(document.contentHash)) continue;

      // Only migrate entries that satisfy the entire current contract except
      // for the (legacy) digest shape — including the file-name <-> batchId
      // binding. Anything else is left untouched and subsequently rejected by
      // the fail-closed load, so a corrupt entry is never silently rewritten.
      let manifest: SharedManifest;
      try {
        manifest = validateSharedManifest(parsed, { allowLegacyContentHash: true });
      } catch (err) {
        if (err instanceof CorruptManifestError) continue;
        throw err;
      }
      if (entry !== this.fileName(manifest.batchId)) continue;

      document.contentHash = this.hasher.migrateLegacyHash(document.contentHash as string);
      const tmp = `${target}.${process.pid}.${Date.now()}.migrate`;
      await writeFile(tmp, JSON.stringify(document), { mode: 0o600 });
      await rename(tmp, target);
      migrated++;
    }
    if (migrated > 0) {
      log.info("legacy_content_hashes_migrated", { manifests: migrated });
    }
  }

  async load(): Promise<void> {
    // Pre-upgrade entries must lose their publicly verifiable digest before
    // any of them can be served or compared.
    await this.migrateLegacyHashes();

    const entries = await readdir(this.dataDir);
    const corrupt: Array<{ file: string; issues: ValidationIssue[] }> = [];
    let count = 0;
    for (const entry of entries.sort()) {
      if (!entry.endsWith(".json")) continue;
      const issues = await this.inspectEntry(entry);
      if (issues.length > 0) {
        corrupt.push({ file: entry, issues });
      } else {
        count++;
      }
    }
    // Report every corrupt entry before aborting so a single restart cycle
    // surfaces all of them. The diagnostics contain only hashed file names,
    // rule codes and JSON paths — corrupt content itself is never logged.
    for (const entry of corrupt) {
      log.error("store_corrupt_entry", {
        file: entry.file,
        issues: JSON.stringify(entry.issues),
      });
    }
    if (corrupt.length > 0) {
      throw new CorruptStoreError(corrupt.map((entry) => entry.file));
    }
    log.info("store_loaded", { manifests: count });
  }

  /**
   * Validate one persisted entry. Returns the list of contract violations
   * (empty when the entry is trustworthy); only fully valid entries are
   * admitted into the in-memory index.
   */
  private async inspectEntry(entry: string): Promise<ValidationIssue[]> {
    let raw: string;
    try {
      raw = await readFile(join(this.dataDir, entry), "utf8");
    } catch {
      return [
        { code: "unreadable_entry", path: "$", message: "persisted manifest could not be read" },
      ];
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return [
        { code: "invalid_json", path: "$", message: "persisted manifest is not valid JSON" },
      ];
    }

    let manifest: SharedManifest;
    try {
      manifest = validateSharedManifest(parsed);
    } catch (err) {
      if (err instanceof CorruptManifestError) return err.issues;
      throw err;
    }

    // The storage key is part of the contract: the file name must be the
    // SHA-256 of the batchId it claims to hold.
    if (entry !== this.fileName(manifest.batchId)) {
      return [
        {
          code: "batch_id_file_mismatch",
          path: "$.batchId",
          message: "batchId does not match the persisted file name binding",
        },
      ];
    }

    this.manifests.set(manifest.batchId, manifest);
    return [];
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
      return existing.contentHash === contentDigest
        ? { status: "replayed", manifest: existing }
        : { status: "conflict" };
    }

    const target = join(this.dataDir, this.fileName(batchId));
    const tmp = `${target}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, JSON.stringify(manifest), { mode: 0o600 });
    await rename(tmp, target);
    this.manifests.set(batchId, manifest);
    return { status: "created", manifest };
  }
}
