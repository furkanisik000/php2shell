// Saf PHP version parse + risk skorlama. chrome.* none, db none.

const VER_RE = /php\/?\s*v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)/i;

/** "PHP/8.4.26", "Apache/2.4.69 (Debian) PHP/8.4.26" -> "8.4.26" | null */
export function extractVersion(text) {
  if (!text || typeof text !== 'string') return null;
  const m = text.match(VER_RE);
  return m ? m[1] : null;
}

/** "8.4.26" -> { major, minor, patch, full } | null. "8.4" da kabul (patch=null). */
export function parseVersion(v) {
  const m = String(v || '').trim().match(/^(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?/);
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: m[3] ? Number(m[3]) : null,
    full: `${m[1]}.${m[2]}${m[3] ? `.${m[3]}` : ''}`,
  };
}

/** "8.4.26" -> "8.4" (branch) | null */
export function branchOf(v) {
  const p = parseVersion(v);
  return p ? `${p.major}.${p.minor}` : null;
}

const STATUS_META = {
  POTENTIAL_RISK: { tone: 'danger', label: 'Potential risk' },
  EOL_NO_PATCH: { tone: 'danger', label: 'End-of-life' },
  CONFIRMED_FIXED: { tone: 'ok', label: 'Fixed' },
  NO_KNOWN_INDICATORS: { tone: 'ok', label: 'No known indicators' },
  DISTRO_BUILD: { tone: 'warn', label: 'Distro build' },
  UNABLE_TO_VERIFY: { tone: 'neutral', label: 'Unverified' },
  INCOMPLETE_VERSION: { tone: 'neutral', label: 'Incomplete' },
};

/** status -> {tone,label}. Bilinmeyen status for neutral. */
export function statusMeta(status) {
  return STATUS_META[status] || { tone: 'neutral', label: status || '—' };
}

function cmpBranch(a, b) {
  if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
  if (a[1] !== b[1]) return a[1] < b[1] ? -1 : 1;
  return 0;
}

/**
 * Rule-based skor (db.json -> rules fallback).
 * @returns {{status:string, tone:string, label:string, reason:string}}
 */
export function scoreVersion(version, rules) {
  const parsed = parseVersion(version);
  if (!parsed) {
    const m = statusMeta('INCOMPLETE_VERSION');
    return { status: 'INCOMPLETE_VERSION', tone: m.tone, label: m.label, reason: 'Version parse edilemedi — x.y(.z) gir.' };
  }
  const branch = [parsed.major, parsed.minor];
  const eol = rules?.eolBefore || [8, 2];
  const fixed = rules?.fixedBranch || null;
  if (cmpBranch(branch, eol) < 0) {
    const m = statusMeta('EOL_NO_PATCH');
    return { status: 'EOL_NO_PATCH', tone: m.tone, label: m.label, reason: `PHP ${parsed.full} EOL branch (< ${eol.join('.')}).` };
  }
  if (fixed && cmpBranch(branch, fixed) >= 0) {
    const m = statusMeta('CONFIRMED_FIXED');
    return { status: 'CONFIRMED_FIXED', tone: m.tone, label: m.label, reason: `PHP ${parsed.full} fixed branch (${fixed.join('.')}) uzerinde.` };
  }
  const m = statusMeta('POTENTIAL_RISK');
  return {
    status: 'POTENTIAL_RISK',
    tone: m.tone,
    label: m.label,
    reason: fixed ? `PHP ${parsed.full} < fixed ${fixed.join('.')}.` : `PHP ${parsed.full} — fixed branch dogrulanmadi; at-risk.`,
  };
}