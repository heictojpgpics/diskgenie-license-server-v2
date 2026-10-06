/**
 * D1 query layer — one place per table so route handlers stay protocol
 * logic, and so every query is reviewable against the schema at once.
 *
 * v2 hardening notes:
 *  * `touchDevice` COALESCEs every nullable column — a claim that omits
 *    a field can never NULL-out stored data (the v1 validate path wiped
 *    hostname/os_version/app_version on every 24 h revalidation; that
 *    was the owner-reported "doesn't save hostname" bug).
 *  * The live-slot rule (1 Windows + 1 macOS per key) is enforced by the
 *    partial unique index `idx_devices_live_slot` — `insertDevice` and
 *    `reviveDevice` map its constraint error to the DEVICE_SLOT_TAKEN
 *    outcome. Storage-level invariant = race-proof by construction
 *    (v1's SELECT-then-INSERT had a TOCTOU window).
 *  * `rateConsume` is a single atomic upsert — concurrent requests
 *    serialize on SQLite's write lock, so counters are exact.
 */
import type { DeviceClaim } from "./types";

export interface LicenseRow {
  id: number;
  key_hash: string;
  key_last4: string;
  tier: "yearly" | "lifetime";
  status: "active" | "revoked" | "refunded" | "pending";
  customer_name: string;
  customer_email: string;
  note: string | null;
  source: string | null;
  issued_at: number;
  expires_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface DeviceRow {
  id: number;
  license_id: number;
  platform: "windows" | "macos";
  hardware_hash: string;
  hostname: string | null;
  os_version: string | null;
  app_version: string | null;
  comp_machine: string | null;
  comp_volume: string | null;
  comp_cpu: string | null;
  cpu_brand: string | null;
  ram_mb: number | null;
  machine_model: string | null;
  baseboard_serial: string | null;
  firmware_uuid: string | null;
  bios_version: string | null;
  cpu_cores: number | null;
  arch: string | null;
  comp_board: string | null;
  comp_firmware: string | null;
  facts_v3: number | null;
  activated_at: number;
  last_seen_at: number;
  revoked: number;
}

export interface AuditRow {
  id: number;
  license_id: number | null;
  key_last4: string | null;
  event: string;
  platform: string | null;
  hw_prefix: string | null;
  reason: string | null;
  ip_hash: string | null;
  detail: string | null;
  created_at: number;
}

/** The slot rule says a UNIQUE-constraint failure on the live-slot
 * index — mapped by the routes to the DEVICE_SLOT_TAKEN contract. */
export class SlotTakenError extends Error {
  constructor() {
    super("device slot taken");
    this.name = "SlotTakenError";
  }
}

/** One licenses-row INSERT (shared by the single-row and batch paths
 *  so the column list + status default live in exactly one place). */
export interface LicenseInsert {
  keyHash: string;
  keyLast4: string;
  tier: "yearly" | "lifetime";
  customerName: string;
  customerEmail: string;
  note: string | null;
  source: string | null;
  issuedAt: number;
  expiresAt: number | null;
  now: number;
}

/** One audit_events-row INSERT (shared by audit() and the atomic batch). */
export interface AuditInsert {
  licenseId?: number | null;
  keyLast4?: string | null;
  event: string;
  platform?: string | null;
  hwPrefix?: string | null;
  reason?: string | null;
  ipHash?: string | null;
  detail?: string | null;
  now: number;
}

/** True when the claim carries ANY v3 field — sets the row's facts_v3
 * provenance marker ("this client already speaks v3"), so support can
 * tell an old client from hardware that refuses to report a fact. */
const claimHasV3 = (claim: DeviceClaim): boolean =>
  claim.baseboardSerial !== undefined ||
  claim.firmwareUuid !== undefined ||
  claim.biosVersion !== undefined ||
  claim.cpuCores !== undefined ||
  claim.arch !== undefined ||
  claim.compBoard !== undefined ||
  claim.compFirmware !== undefined;

const isSlotConstraint = (err: unknown): boolean => {
  const msg = err instanceof Error ? err.message : String(err);
  // D1 surfaces SQLite's message: "UNIQUE constraint failed: devices.license_id, devices.platform"
  return msg.includes("UNIQUE constraint failed") && msg.includes("devices.");
};

/** The licenses INSERT shared by the single-row and batch paths — the
 *  column list + the 'active' status default live in exactly one place. */
const LICENSE_INSERT_SQL = `
  INSERT INTO licenses
    (key_hash, key_last4, tier, status, customer_name, customer_email,
     note, source, issued_at, expires_at, created_at, updated_at)
  VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)`;

const LICENSE_INSERT_BINDS = (l: LicenseInsert): unknown[] => [
  l.keyHash,
  l.keyLast4,
  l.tier,
  l.customerName,
  l.customerEmail,
  l.note,
  l.source,
  l.issuedAt,
  l.expiresAt,
  l.now,
];

export class Db {
  constructor(private readonly d1: D1Database) {}

  // ── licenses ──────────────────────────────────────────────────────

  licenseByHash(keyHash: string): Promise<LicenseRow | null> {
    return this.d1
      .prepare("SELECT * FROM licenses WHERE key_hash = ?1")
      .bind(keyHash)
      .first<LicenseRow>();
  }

  licenseById(id: number): Promise<LicenseRow | null> {
    return this.d1
      .prepare("SELECT * FROM licenses WHERE id = ?1")
      .bind(id)
      .first<LicenseRow>();
  }

  licensesPage(offset: number, limit: number, email?: string): Promise<LicenseRow[]> {
    if (email !== undefined) {
      return this.d1
        .prepare("SELECT * FROM licenses WHERE customer_email = ?1 ORDER BY id DESC LIMIT ?2 OFFSET ?3")
        .bind(email, limit, offset)
        .all<LicenseRow>()
        .then((r) => r.results);
    }
    return this.d1
      .prepare("SELECT * FROM licenses ORDER BY id DESC LIMIT ?1 OFFSET ?2")
      .bind(limit, offset)
      .all<LicenseRow>()
      .then((r) => r.results);
  }

  countLicenses(email?: string): Promise<number> {
    if (email !== undefined) {
      return this.d1
        .prepare("SELECT COUNT(*) AS n FROM licenses WHERE customer_email = ?1")
        .bind(email)
        .first<{ n: number }>()
        .then((r) => r?.n ?? 0);
    }
    return this.d1
      .prepare("SELECT COUNT(*) AS n FROM licenses")
      .first<{ n: number }>()
      .then((r) => r?.n ?? 0);
  }

  /** The prepared licenses INSERT (columns/status in one place — shared
   *  by the atomic batch below; the generate route is the only writer). */
  private licenseInsertStatement(license: LicenseInsert): D1PreparedStatement {
    return this.d1.prepare(LICENSE_INSERT_SQL).bind(...LICENSE_INSERT_BINDS(license));
  }

  /** Idempotency-marker lookup (admin batch generation): every key of an
   *  idempotent batch carries `idem:<sha256(idempotency-key)>` in
   *  `source` — see routes/admin.ts. */
  licensesBySource(source: string): Promise<LicenseRow[]> {
    return this.d1
      .prepare("SELECT * FROM licenses WHERE source = ?1 ORDER BY id")
      .bind(source)
      .all<LicenseRow>()
      .then((r) => r.results);
  }

  /**
   * Insert a WHOLE generation batch + its audit row in ONE D1 `batch()`
   * call — an implicit transaction: every statement commits or none
   * does. The admin generate route previously inserted keys one-by-one,
   * so a mid-loop failure left earlier keys committed while their raw
   * values were already lost to the caller (only hashes persist — the
   * raw keys were unrecoverable). Atomicity restores all-or-nothing
   * semantics (principles: transactions enforce the invariants, not
   * check-then-write application code).
   */
  insertLicensesAtomic(licenses: LicenseInsert[], audit: AuditInsert): Promise<void> {
    const stmts = licenses.map((l) => this.licenseInsertStatement(l));
    stmts.push(this.auditStatement(audit));
    return this.d1.batch(stmts).then(() => undefined);
  }

  setLicenseStatus(id: number, status: LicenseRow["status"], now: number): Promise<void> {
    return this.d1
      .prepare("UPDATE licenses SET status = ?2, updated_at = ?3 WHERE id = ?1")
      .bind(id, status, now)
      .run()
      .then(() => undefined);
  }

  extendLicenseExpiry(id: number, expiresAt: number | null, now: number): Promise<void> {
    return this.d1
      .prepare("UPDATE licenses SET expires_at = ?2, updated_at = ?3 WHERE id = ?1")
      .bind(id, expiresAt, now)
      .run()
      .then(() => undefined);
  }

  /** Update customer identity (support: email change / name fix). */
  transferLicense(id: number, name: string, email: string, now: number): Promise<void> {
    return this.d1
      .prepare("UPDATE licenses SET customer_name = ?2, customer_email = ?3, updated_at = ?4 WHERE id = ?1")
      .bind(id, name, email, now)
      .run()
      .then(() => undefined);
  }

  licenseCounts(): Promise<{ tier: string; status: string; n: number }[]> {
    return this.d1
      .prepare("SELECT tier, status, COUNT(*) AS n FROM licenses GROUP BY tier, status")
      .all<{ tier: string; status: string; n: number }>()
      .then((r) => r.results);
  }

  // ── devices ───────────────────────────────────────────────────────

  deviceByLicensePlatformHw(
    licenseId: number,
    platform: "windows" | "macos",
    hardwareHash: string,
  ): Promise<DeviceRow | null> {
    return this.d1
      .prepare("SELECT * FROM devices WHERE license_id = ?1 AND platform = ?2 AND hardware_hash = ?3")
      .bind(licenseId, platform, hardwareHash)
      .first<DeviceRow>();
  }

  liveDevicesForPlatform(
    licenseId: number,
    platform: "windows" | "macos",
  ): Promise<DeviceRow[]> {
    return this.d1
      .prepare("SELECT * FROM devices WHERE license_id = ?1 AND platform = ?2 AND revoked = 0")
      .bind(licenseId, platform)
      .all<DeviceRow>()
      .then((r) => r.results);
  }

  devicesOfLicense(licenseId: number): Promise<DeviceRow[]> {
    return this.d1
      .prepare("SELECT * FROM devices WHERE license_id = ?1 ORDER BY id")
      .bind(licenseId)
      .all<DeviceRow>()
      .then((r) => r.results);
  }

  /** Global device census (admin overview; newest first). */
  devicesPage(offset: number, limit: number): Promise<DeviceRow[]> {
    return this.d1
      .prepare(
        `SELECT * FROM devices ORDER BY last_seen_at DESC, id DESC LIMIT ?1 OFFSET ?2`,
      )
      .bind(limit, offset)
      .all<DeviceRow>()
      .then((r) => r.results);
  }

  /** Global device census joined with the license identity (admin). */
  devicesWithLicense(offset: number, limit: number): Promise<(DeviceRow & { key_last4: string; customer_email: string; customer_name: string; tier: string })[]> {
    return this.d1
      .prepare(
        `SELECT d.*, l.key_last4, l.customer_email, l.customer_name, l.tier
         FROM devices d JOIN licenses l ON l.id = d.license_id
         ORDER BY d.last_seen_at DESC, d.id DESC LIMIT ?1 OFFSET ?2`,
      )
      .bind(limit, offset)
      .all<DeviceRow & { key_last4: string; customer_email: string; customer_name: string; tier: string }>()
      .then((r) => r.results);
  }

  countDevices(): Promise<number> {
    return this.d1
      .prepare("SELECT COUNT(*) AS n FROM devices WHERE revoked = 0")
      .first<{ n: number }>()
      .then((r) => r?.n ?? 0);
  }

  devicesByPlatform(): Promise<{ platform: string; n: number }[]> {
    return this.d1
      .prepare("SELECT platform, COUNT(*) AS n FROM devices WHERE revoked = 0 GROUP BY platform")
      .all<{ platform: string; n: number }>()
      .then((r) => r.results);
  }

  insertDevice(licenseId: number, claim: DeviceClaim, now: number): Promise<DeviceRow> {
    return this.d1
      .prepare(
        `INSERT INTO devices
           (license_id, platform, hardware_hash, hostname, os_version, app_version,
            comp_machine, comp_volume, comp_cpu, cpu_brand, ram_mb, machine_model,
            baseboard_serial, firmware_uuid, bios_version, cpu_cores, arch,
            comp_board, comp_firmware, facts_v3,
            activated_at, last_seen_at, revoked)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                 ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                 ?21, ?21, 0)
         RETURNING *`,
      )
      .bind(
        licenseId,
        claim.platform,
        claim.hardwareHash,
        claim.hostname ?? null,
        claim.osVersion ?? null,
        claim.appVersion ?? null,
        claim.compMachine ?? null,
        claim.compVolume ?? null,
        claim.compCpu ?? null,
        claim.cpuBrand ?? null,
        claim.ramMb ?? null,
        claim.machineModel ?? null,
        claim.baseboardSerial ?? null,
        claim.firmwareUuid ?? null,
        claim.biosVersion ?? null,
        claim.cpuCores ?? null,
        claim.arch ?? null,
        claim.compBoard ?? null,
        claim.compFirmware ?? null,
        claimHasV3(claim) ? 1 : null,
        now,
      )
      .first<DeviceRow>()
      .catch((err: unknown) => {
        // The partial unique live-slot index fired: another live device
        // holds this platform slot (race lost, or v1 race duplicate).
        if (isSlotConstraint(err)) throw new SlotTakenError();
        throw err;
      })
      .then((r) => {
        if (!r) throw new Error("insert device returned no row");
        return r;
      });
  }

  /**
   * Refresh the device row from a claim. v2 contract: NEVER regress a
   * stored value to NULL — every nullable column COALESCEs, so a claim
   * that omits facts (older client, partial collection) keeps the last
   * known good value. This is the fix for the v1 wipe bug.
   */
  touchDevice(id: number, claim: DeviceClaim, now: number): Promise<void> {
    return this.d1
      .prepare(
        `UPDATE devices SET
           last_seen_at = ?2,
           hostname = COALESCE(?3, hostname),
           os_version = COALESCE(?4, os_version),
           app_version = COALESCE(?5, app_version),
           comp_machine = COALESCE(?6, comp_machine),
           comp_volume = COALESCE(?7, comp_volume),
           comp_cpu = COALESCE(?8, comp_cpu),
           cpu_brand = COALESCE(?9, cpu_brand),
           ram_mb = COALESCE(?10, ram_mb),
           machine_model = COALESCE(?11, machine_model),
           baseboard_serial = COALESCE(?12, baseboard_serial),
           firmware_uuid = COALESCE(?13, firmware_uuid),
           bios_version = COALESCE(?14, bios_version),
           cpu_cores = COALESCE(?15, cpu_cores),
           arch = COALESCE(?16, arch),
           comp_board = COALESCE(?17, comp_board),
           comp_firmware = COALESCE(?18, comp_firmware),
           facts_v3 = COALESCE(?19, facts_v3)
         WHERE id = ?1`,
      )
      .bind(
        id,
        now,
        claim.hostname ?? null,
        claim.osVersion ?? null,
        claim.appVersion ?? null,
        claim.compMachine ?? null,
        claim.compVolume ?? null,
        claim.compCpu ?? null,
        claim.cpuBrand ?? null,
        claim.ramMb ?? null,
        claim.machineModel ?? null,
        claim.baseboardSerial ?? null,
        claim.firmwareUuid ?? null,
        claim.biosVersion ?? null,
        claim.cpuCores ?? null,
        claim.arch ?? null,
        claim.compBoard ?? null,
        claim.compFirmware ?? null,
        claimHasV3(claim) ? 1 : null,
      )
      .run()
      .then(() => undefined);
  }

  /**
   * Reactivate a support-reset row for the SAME hardware — atomically
   * refuses when another live device already holds the platform slot
   * (the partial unique index is the invariant; the NOT EXISTS
   * subquery keeps the UPDATE and the index in one serialized step).
   * Returns the refreshed row, or throws SlotTakenError.
   */
  reviveDevice(licenseId: number, id: number, platform: "windows" | "macos", now: number): Promise<DeviceRow> {
    return this.d1
      .prepare(
        `UPDATE devices SET revoked = 0, last_seen_at = ?3
         WHERE id = ?4 AND license_id = ?1 AND platform = ?2
           AND NOT EXISTS (
             SELECT 1 FROM devices d
             WHERE d.license_id = ?1 AND d.platform = ?2 AND d.revoked = 0 AND d.id != ?4
           )
         RETURNING *`,
      )
      .bind(licenseId, platform, now, id)
      .first<DeviceRow>()
      .then((r) => {
        if (!r) throw new SlotTakenError();
        return r;
      });
  }

  revokeDevice(id: number, now: number): Promise<void> {
    return this.d1
      .prepare("UPDATE devices SET revoked = 1, last_seen_at = ?2 WHERE id = ?1")
      .bind(id, now)
      .run()
      .then(() => undefined);
  }

  /** Support undo for a device reset (idempotent-safe: same guard as revive). */
  reviveDeviceById(id: number, now: number): Promise<DeviceRow | null> {
    return this.d1
      .prepare("UPDATE devices SET revoked = 0, last_seen_at = ?2 WHERE id = ?1 RETURNING *")
      .bind(id, now)
      .first<DeviceRow>();
  }

  deviceById(id: number): Promise<DeviceRow | null> {
    return this.d1
      .prepare("SELECT * FROM devices WHERE id = ?1")
      .bind(id)
      .first<DeviceRow>();
  }

  // ── audit ─────────────────────────────────────────────────────────

  /** The prepared audit INSERT (shared by audit() + the atomic batch). */
  private auditStatement(event: AuditInsert): D1PreparedStatement {
    return this.d1
      .prepare(
        `INSERT INTO audit_events
           (license_id, key_last4, event, platform, hw_prefix, reason, ip_hash, detail, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`,
      )
      .bind(
        event.licenseId ?? null,
        event.keyLast4 ?? null,
        event.event,
        event.platform ?? null,
        event.hwPrefix ?? null,
        event.reason ?? null,
        event.ipHash ?? null,
        event.detail ?? null,
        event.now,
      );
  }

  audit(event: AuditInsert): Promise<void> {
    return this.auditStatement(event).run().then(() => undefined);
  }

  recentAudit(limit: number): Promise<AuditRow[]> {
    return this.d1
      .prepare("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?1")
      .bind(limit)
      .all<AuditRow>()
      .then((r) => r.results);
  }

  /** Retention: drop audit rows older than the horizon (housekeeping). */
  sweepAudit(now: number, olderThanSeconds: number): Promise<void> {
    return this.d1
      .prepare("DELETE FROM audit_events WHERE created_at < ?1")
      .bind(now - olderThanSeconds)
      .run()
      .then(() => undefined);
  }

  auditCountSince(since: number, event: string): Promise<number> {
    return this.d1
      .prepare("SELECT COUNT(*) AS n FROM audit_events WHERE event = ?1 AND created_at >= ?2")
      .bind(event, since)
      .first<{ n: number }>()
      .then((r) => r?.n ?? 0);
  }

  // ── nonce replay defense ──────────────────────────────────────────

  /** Returns true when the nonce is fresh (and records it). */
  consumeNonce(nonce: string, now: number): Promise<boolean> {
    return this.d1
      .prepare("INSERT INTO nonce_seen (nonce, seen_at) VALUES (?1, ?2)")
      .bind(nonce, now)
      .run()
      .then(() => true)
      .catch(() => false);
  }

  /** Housekeeping: drop nonces + rate buckets older than the window. */
  sweepNonces(now: number, olderThanSeconds: number): Promise<void> {
    return this.d1
      .prepare("DELETE FROM nonce_seen WHERE seen_at < ?1")
      .bind(now - olderThanSeconds)
      .run()
      .then(() =>
        this.d1
          .prepare("DELETE FROM rate_buckets WHERE window_start < ?1")
          .bind(now - olderThanSeconds - 3_600)
          .run(),
      )
      .then(() => undefined);
  }

  // ── rate limiting (fixed window, atomic upsert) ────────────────────

  /**
   * Consume one unit of the bucket `key`. Returns false when the limit
   * for the current window is already exhausted (→ HTTP 429). The
   * upsert is a single statement — SQLite serializes writers, so the
   * counter is exact under concurrency.
   */
  rateConsume(key: string, limit: number, windowSec: number, now: number): Promise<boolean> {
    const windowStart = Math.floor(now / windowSec) * windowSec;
    return this.d1
      .prepare(
        `INSERT INTO rate_buckets (bucket_key, window_start, count) VALUES (?1, ?2, 1)
         ON CONFLICT(bucket_key) DO UPDATE SET
           count = CASE WHEN window_start = ?2 THEN count + 1 ELSE 1 END,
           window_start = ?2
         RETURNING count`,
      )
      .bind(key, windowStart)
      .first<{ count: number }>()
      .then((r) => (r?.count ?? 1) <= limit);
  }
}
