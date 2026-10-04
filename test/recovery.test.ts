import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Aliaser } from "../src/alias.ts";
import { canonicalize } from "../src/canonical.ts";
import {
  MIGRATED_CONTENT_KEY_ID,
  contentKeyId,
  deriveContentKey,
  neutralizedLegacyContentHash,
  publicContentHash,
} from "../src/contentKey.ts";
import { validatePersistedManifest, validateSharedManifest } from "../src/sharedValidation.ts";
import { CorruptStoreError, ManifestStore } from "../src/store.ts";
import { CorruptManifestError } from "../src/types.ts";
import { transformBatch } from "../src/transform.ts";
import { validateBatch } from "../src/validation.ts";

const SECRET = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
const CONTENT_KEY = deriveContentKey(SECRET);
const KEY_ID = contentKeyId(CONTENT_KEY);

function fileNameFor(batchId: string): string {
  return createHash("sha256").update(batchId, "utf8").digest("hex") + ".json";
}

/** Plain unkeyed SHA-256 as produced by the pre-upgrade write path. */
function legacyContentHash(batch: ReturnType<typeof validateBatch>): string {
  return createHash("sha256").update(canonicalize(batch), "utf8").digest("hex");
}

function validBody(batchId: string): Record<string, unknown> {
  return {
    batchId,
    records: [
      {
        recordId: "R-001",
        patientId: "PAT-1",
        accessionId: "ACC-1",
        relatedIds: ["R-002"],
        measurements: { tumorSizeMm: 12.5, reviewed: true, note: null },
      },
      {
        recordId: "R-002",
        patientId: "PAT-2",
        accessionId: "ACC-2",
        relatedIds: [],
        measurements: { ki67: 30 },
      },
    ],
  };
}

/**
 * The confirmed corrupt restore sample: the file name matches the current
 * hashing rule and the JSON parses, but the alias fields carry raw
 * identifiers and both contentHash and createdAt are malformed.
 */
const CORRUPT_SAMPLE = {
  batchId: "restore-batch",
  createdAt: "not-a-timestamp",
  contentHash: "not-a-valid-hash",
  records: [
    {
      recordAlias: "HOSPITAL-REC-900",
      patientAlias: "PATIENT-900",
      accessionAlias: "ACCESSION-900",
      relatedAliases: ["HOSPITAL-REC-900"],
      measurements: {},
    },
  ],
};
const CORRUPT_RAW_IDS = ["PATIENT-900", "ACCESSION-900", "HOSPITAL-REC-900"];

async function writeEntry(dir: string, fileName: string, value: unknown): Promise<void> {
  await writeFile(join(dir, fileName), typeof value === "string" ? value : JSON.stringify(value));
}

test("recovery: a valid persisted manifest survives a restart", async () => {
  const dir = mkdtempSync(join(tmpdir(), "manifest-recovery-ok-"));
  const batch = validateBatch(validBody("batch-restore-ok"));
  const hash = publicContentHash(batch, CONTENT_KEY);
  const manifest = transformBatch(batch, new Aliaser(SECRET), hash, KEY_ID);

  const first = new ManifestStore(dir, CONTENT_KEY);
  assert.equal((await first.create(batch.batchId, hash, manifest)).status, "created");

  const restarted = new ManifestStore(dir, CONTENT_KEY);
  await restarted.load();
  assert.deepEqual(restarted.get("batch-restore-ok"), manifest);
  // Idempotency/conflict semantics are intact over restored entries.
  assert.equal((await restarted.create(batch.batchId, hash, manifest)).status, "replayed");
  assert.equal((await restarted.create(batch.batchId, "different-hash", manifest)).status, "conflict");
});

test("recovery: the corrupt restore-batch sample aborts startup and is never served", async () => {
  const dir = mkdtempSync(join(tmpdir(), "manifest-recovery-corrupt-"));

  // A fully valid entry sits next to the corrupt one.
  const batch = validateBatch(validBody("batch-healthy"));
  const hash = publicContentHash(batch, CONTENT_KEY);
  const first = new ManifestStore(dir, CONTENT_KEY);
  await first.create(batch.batchId, hash, transformBatch(batch, new Aliaser(SECRET), hash, KEY_ID));

  await writeEntry(dir, fileNameFor("restore-batch"), CORRUPT_SAMPLE);

  const restarted = new ManifestStore(dir, CONTENT_KEY);
  let failure: unknown;
  try {
    await restarted.load();
  } catch (err) {
    failure = err;
  }
  assert.ok(failure instanceof CorruptStoreError, "corrupt entry must abort the load");
  assert.deepEqual((failure as InstanceType<typeof CorruptStoreError>).files, [
    fileNameFor("restore-batch"),
  ]);

  // Diagnostics (error text + validation issues) must never contain the raw
  // identifiers embedded in the corrupt file.
  let issuesText = "";
  try {
    validateSharedManifest(CORRUPT_SAMPLE);
    assert.fail("corrupt sample must fail contract validation");
  } catch (err) {
    issuesText = JSON.stringify((err as { issues: unknown }).issues);
  }
  for (const raw of CORRUPT_RAW_IDS) {
    assert.ok(!(failure as Error).message.includes(raw), `error must not contain ${raw}`);
    assert.ok(!issuesText.includes(raw), `issues must not contain ${raw}`);
  }

  // The corrupt entry is never admitted into the index, so it cannot be
  // returned by GET even if a caller wrongly ignored the load failure.
  assert.equal(restarted.get("restore-batch"), undefined);
});

test("recovery: duplicate record aliases in a persisted entry are rejected", async () => {
  const dir = mkdtempSync(join(tmpdir(), "manifest-recovery-dup-"));
  const alias = `rec-${"a".repeat(32)}`;
  const record = {
    recordAlias: alias,
    patientAlias: `pat-${"b".repeat(32)}`,
    accessionAlias: `acc-${"c".repeat(32)}`,
    relatedAliases: [],
    measurements: {},
  };
  await writeEntry(dir, fileNameFor("batch-dup-alias"), {
    batchId: "batch-dup-alias",
    createdAt: "2026-10-04T00:00:00.000Z",
    contentHash: "0".repeat(64),
    contentKeyId: KEY_ID,
    records: [record, { ...record }],
  });

  const store = new ManifestStore(dir, CONTENT_KEY);
  await assert.rejects(store.load(), CorruptStoreError);
  assert.equal(store.get("batch-dup-alias"), undefined);
});

test("recovery: unclosed references in a persisted entry are rejected", async () => {
  const dir = mkdtempSync(join(tmpdir(), "manifest-recovery-dangling-"));
  await writeEntry(dir, fileNameFor("batch-dangling-alias"), {
    batchId: "batch-dangling-alias",
    createdAt: "2026-10-04T00:00:00.000Z",
    contentHash: "0".repeat(64),
    contentKeyId: KEY_ID,
    records: [
      {
        recordAlias: `rec-${"a".repeat(32)}`,
        patientAlias: `pat-${"b".repeat(32)}`,
        accessionAlias: `acc-${"c".repeat(32)}`,
        relatedAliases: [`rec-${"d".repeat(32)}`],
        measurements: {},
      },
    ],
  });

  const store = new ManifestStore(dir, CONTENT_KEY);
  await assert.rejects(store.load(), CorruptStoreError);
  assert.equal(store.get("batch-dangling-alias"), undefined);
});

test("recovery: file name must match the SHA-256 binding of its batchId", async () => {
  const dir = mkdtempSync(join(tmpdir(), "manifest-recovery-binding-"));
  const batch = validateBatch(validBody("batch-binding"));
  const hash = publicContentHash(batch, CONTENT_KEY);
  const manifest = transformBatch(batch, new Aliaser(SECRET), hash, KEY_ID);
  // Persist the valid document under the WRONG file name.
  await writeEntry(dir, fileNameFor("some-other-batch"), manifest);

  const store = new ManifestStore(dir, CONTENT_KEY);
  await assert.rejects(store.load(), CorruptStoreError);
  assert.equal(store.get("batch-binding"), undefined);
});

test("recovery: syntactically broken JSON entries abort startup too", async () => {
  const dir = mkdtempSync(join(tmpdir(), "manifest-recovery-json-"));
  await writeEntry(dir, fileNameFor("batch-broken"), "{not valid json");

  const store = new ManifestStore(dir, CONTENT_KEY);
  await assert.rejects(store.load(), CorruptStoreError);
});

test("shared manifest contract: field set, formats and scalar measurements", () => {
  const batch = validateBatch(validBody("batch-contract"));
  const good = transformBatch(batch, new Aliaser(SECRET), publicContentHash(batch, CONTENT_KEY), KEY_ID);
  // A manifest produced by the write path always satisfies the contract.
  assert.deepEqual(validateSharedManifest(JSON.parse(JSON.stringify(good))), good);

  const cases: Array<{ name: string; mutate: (m: any) => void; code: string }> = [
    { name: "unknown top-level field", mutate: (m) => (m.extra = 1), code: "manifest_unknown_field" },
    { name: "missing createdAt", mutate: (m) => delete m.createdAt, code: "invalid_created_at" },
    {
      name: "createdAt not a timestamp",
      mutate: (m) => (m.createdAt = "yesterday"),
      code: "invalid_created_at",
    },
    {
      name: "createdAt impossible date",
      mutate: (m) => (m.createdAt = "2026-13-40T00:00:00.000Z"),
      code: "invalid_created_at",
    },
    {
      name: "contentHash not hex",
      mutate: (m) => (m.contentHash = "zz".repeat(32)),
      code: "invalid_content_hash",
    },
    {
      name: "contentHash wrong length",
      mutate: (m) => (m.contentHash = "abcd"),
      code: "invalid_content_hash",
    },
    {
      name: "missing contentKeyId",
      mutate: (m) => delete m.contentKeyId,
      code: "missing_content_key_id",
    },
    {
      name: "malformed contentKeyId",
      mutate: (m) => (m.contentKeyId = "not a valid key id!"),
      code: "invalid_content_key_id",
    },
    {
      name: "raw id in patientAlias",
      mutate: (m) => (m.records[0].patientAlias = "PATIENT-900"),
      code: "invalid_patient_alias",
    },
    {
      name: "uppercase hex alias",
      mutate: (m) => (m.records[0].recordAlias = `rec-${"A".repeat(32)}`),
      code: "invalid_record_alias",
    },
    {
      name: "unknown record field",
      mutate: (m) => (m.records[0].patientId = "PAT-1"),
      code: "record_unknown_field",
    },
    {
      name: "non-scalar measurement",
      mutate: (m) => (m.records[0].measurements.nested = { leak: 1 }),
      code: "invalid_measurement_value",
    },
    {
      name: "array measurement",
      mutate: (m) => (m.records[0].measurements.tumorSizeMm = [12.5]),
      code: "invalid_measurement_value",
    },
    {
      name: "relatedAliases not an array",
      mutate: (m) => (m.records[0].relatedAliases = "rec-1"),
      code: "related_aliases_not_array",
    },
    {
      name: "duplicate related alias",
      mutate: (m) => (m.records[0].relatedAliases = [m.records[1].recordAlias, m.records[1].recordAlias]),
      code: "duplicate_related_alias",
    },
    {
      name: "empty records",
      mutate: (m) => (m.records = []),
      code: "invalid_records",
    },
  ];

  for (const c of cases) {
    const mutated = JSON.parse(JSON.stringify(good));
    c.mutate(mutated);
    assert.throws(
      () => validateSharedManifest(mutated),
      (err: unknown) => {
        const issues = (err as { issues: { code: string }[] }).issues;
        return issues.some((i) => i.code === c.code);
      },
      c.name,
    );
  }
});

test("recovery: strict validator rejects, legacy recovery accepts, an unkeyed pre-upgrade document", () => {
  const batch = validateBatch(validBody("batch-legacy-shape"));
  const v1 = transformBatch(batch, new Aliaser(SECRET), legacyContentHash(batch), KEY_ID);
  const legacyDoc = JSON.parse(JSON.stringify(v1));
  delete legacyDoc.contentKeyId; // exactly the persisted pre-upgrade shape

  assert.throws(
    () => validateSharedManifest(legacyDoc),
    (err: unknown) =>
      (err as { issues: { code: string }[] }).issues.some((i) => i.code === "missing_content_key_id"),
  );
  const recovered = validatePersistedManifest(legacyDoc, true);
  assert.equal(recovered.legacyUnkeyed, true);
  assert.deepEqual(recovered.manifest, { ...v1, contentKeyId: "" });
  // Recovery without the legacy allowance stays strict.
  assert.throws(() => validatePersistedManifest(legacyDoc, false), CorruptManifestError);
});

test("recovery: pre-upgrade unkeyed manifest stays queryable but its hash oracle is neutralized", async () => {
  const dir = mkdtempSync(join(tmpdir(), "manifest-recovery-legacy-"));
  const batch = validateBatch(validBody("batch-legacy"));
  const oldHash = legacyContentHash(batch);

  // Simulate a file written by the pre-upgrade build: no contentKeyId, plain
  // SHA-256 of the raw business content.
  const legacyDoc = {
    batchId: batch.batchId,
    createdAt: "2026-09-30T00:00:00.000Z",
    contentHash: oldHash,
    records: transformBatch(batch, new Aliaser(SECRET), oldHash, KEY_ID).records,
  };
  await writeEntry(dir, fileNameFor(batch.batchId), legacyDoc);

  const store = new ManifestStore(dir, CONTENT_KEY);
  await store.load(); // must not abort: the legacy entry is otherwise contract-valid

  // Still queryable after the upgrade, with the alias-only body intact.
  const served = store.get(batch.batchId);
  assert.ok(served, "a legitimate pre-upgrade manifest must remain queryable");
  assert.equal(served!.records.length, 2);
  assert.equal(served!.contentKeyId, MIGRATED_CONTENT_KEY_ID);

  // The exposed hash is no longer the plain oracle, nor a plain transform of
  // it: it must be the keyed neutralization, not reproducible without the key.
  assert.notEqual(served!.contentHash, oldHash);
  assert.equal(
    served!.contentHash,
    neutralizedLegacyContentHash(oldHash, CONTENT_KEY),
  );
  assert.notEqual(
    served!.contentHash,
    createHash("sha256").update(oldHash, "utf8").digest("hex"),
    "an unkeyed transform of the old hash would remain an oracle",
  );

  // The on-disk file is rewritten (persisted neutralization), and a second
  // restart converges to exactly the same value (idempotent, one-time).
  const onDisk = JSON.parse(await readFile(join(dir, fileNameFor(batch.batchId)), "utf8"));
  assert.equal(onDisk.contentHash, served!.contentHash);
  assert.equal(onDisk.contentKeyId, MIGRATED_CONTENT_KEY_ID);
  const restartedAgain = new ManifestStore(dir, CONTENT_KEY);
  await restartedAgain.load();
  assert.deepEqual(restartedAgain.get(batch.batchId), served);

  // Enumerating candidate identifiers against the neutralized result fails:
  // no plain digest of any guessed content matches the exposed value.
  for (const candidatePatient of ["PAT-0", "PAT-1", "PAT-2"]) {
    const guessed = validBody("batch-legacy");
    (guessed.records as any[])[0].patientId = candidatePatient;
    const plainGuess = legacyContentHash(validateBatch(guessed));
    assert.notEqual(plainGuess, served!.contentHash);
    // And the pre-upgrade hash (which the candidate owner could have stored)
    // cannot be turned into the new value without the deployment key.
    assert.notEqual(
      neutralizedLegacyContentHash(plainGuess, deriveContentKey(Buffer.from("x".repeat(32), "utf8"))),
      served!.contentHash,
    );
  }

  // Re-submissions against a neutralized entry cannot be proven equal (the
  // original identifiers are gone), so they answer with the existing 409 —
  // both for identical and for different business content.
  const rebuilt = transformBatch(
    batch,
    new Aliaser(SECRET),
    publicContentHash(batch, CONTENT_KEY),
    KEY_ID,
  );
  assert.equal(
    (await store.create(batch.batchId, publicContentHash(batch, CONTENT_KEY), rebuilt)).status,
    "conflict",
  );
  const changed = validateBatch(validBody("batch-legacy"));
  (changed.records as any[])[1].measurements.ki67 = 31;
  assert.equal(
    (await store.create(batch.batchId, publicContentHash(changed, CONTENT_KEY), rebuilt)).status,
    "conflict",
  );
});

test("recovery: neutralization is keyed per deployment, so saved digests cannot be confirmed elsewhere", async () => {
  const dirA = mkdtempSync(join(tmpdir(), "manifest-recovery-legacy-a-"));
  const dirB = mkdtempSync(join(tmpdir(), "manifest-recovery-legacy-b-"));
  const batch = validateBatch(validBody("batch-legacy-keys"));
  const oldHash = legacyContentHash(batch);
  const legacyDoc = {
    batchId: batch.batchId,
    createdAt: "2026-09-30T00:00:00.000Z",
    contentHash: oldHash,
    records: transformBatch(batch, new Aliaser(SECRET), oldHash, KEY_ID).records,
  };
  await writeEntry(dirA, fileNameFor(batch.batchId), legacyDoc);
  await writeEntry(dirB, fileNameFor(batch.batchId), legacyDoc);

  const otherKey = deriveContentKey(Buffer.from("fedcba9876543210fedcba9876543210", "utf8"));
  const storeA = new ManifestStore(dirA, CONTENT_KEY);
  const storeB = new ManifestStore(dirB, otherKey);
  await storeA.load();
  await storeB.load();
  assert.notEqual(
    storeA.get(batch.batchId)!.contentHash,
    storeB.get(batch.batchId)!.contentHash,
    "the same pre-upgrade hash neutralizes differently per deployment key",
  );
});
