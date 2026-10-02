// Randomized differential cases: node-semver (strict, includePrerelease).
const semver = require('/Users/ivan/.nvm/versions/node/v24.11.1/lib/node_modules/npm/node_modules/semver');
const fs = require('fs');

// deterministic PRNG
let seed = 20261003;
const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
const pick = (arr) => arr[Math.floor(rnd() * arr.length)];
const int = (n) => Math.floor(rnd() * n);

const preIds = ['alpha', 'beta', 'rc', '0', '1', '11', 'x-y', 'alpha.1', 'rc.2'];
function randVersion() {
  let v = `${int(4)}.${int(10)}.${int(20)}`;
  if (rnd() < 0.45) v += '-' + pick(preIds);
  if (rnd() < 0.15) v += '+build.' + int(100);
  if (rnd() < 0.1) v = 'v' + v;
  return v;
}
function randPartial() {
  const r = rnd();
  const M = String(int(4)), m = String(int(10)), p = String(int(20));
  if (r < 0.45) return `${M}.${m}.${p}` + (rnd() < 0.35 ? '-' + pick(preIds) : '');
  if (r < 0.6) return `${M}.${m}`;
  if (r < 0.7) return `${M}`;
  if (r < 0.8) return `${M}.${m}.x`;
  if (r < 0.9) return `${M}.x`;
  return 'x';
}
function randComparator() {
  const r = rnd();
  if (r < 0.15) return '^' + randPartial();
  if (r < 0.3) return '~' + randPartial();
  if (r < 0.75) return pick(['', '=', '<', '<=', '>', '>=']) + randPartial();
  if (r < 0.85) return randPartial();
  // hyphen range
  return randPartial() + ' - ' + randPartial();
}
function randRange() {
  const sets = 1 + int(2);
  const parts = [];
  for (let i = 0; i < sets; i++) {
    const n = 1 + int(3);
    const comps = [];
    for (let j = 0; j < n; j++) comps.push(randComparator());
    parts.push(comps.join(' '));
  }
  return parts.join(' || ');
}

const N = 3000;
const out = { ranges: [], invalidRanges: [], compares: [] };
for (let i = 0; i < N; i++) {
  const range = randRange();
  const version = randVersion();
  let rangeObj;
  try {
    rangeObj = new semver.Range(range, { includePrerelease: true });
  } catch (e) {
    out.invalidRanges.push(range);
    continue;
  }
  out.ranges.push({ range, version, expected: rangeObj.test(version) });
}
for (let i = 0; i < 1500; i++) {
  const a = randVersion(), b = randVersion();
  try {
    out.compares.push({ a, b, expected: semver.compare(a, b) });
  } catch (e) { /* invalid generated version; skip */ }
}
fs.writeFileSync('testdata/npm_fuzz.json', JSON.stringify(out));
console.log('npm fuzz cases:', out.ranges.length, 'invalid ranges:', out.invalidRanges.length, 'compares:', out.compares.length);
