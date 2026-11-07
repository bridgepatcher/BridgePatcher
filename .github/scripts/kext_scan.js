// Malware checks for the kexts themselves.
//
// The kexts in payloads/ ship as .zip files, so the line-based rules of the malware
// scanners never saw what is inside them, and ClamAV only knows already identified samples.
// This module opens the archives (in memory, nothing is extracted to disk or executed) and
// checks:
//
//   - every kext's executable (X.kext/Contents/MacOS/...): it must be a Mach-O kernel
//     extension (MH_KEXT_BUNDLE, or MH_OBJECT for very old kexts) in every architecture
//     slice. A normal program, library or script disguised as a kext is reported.
//   - text files inside the archives (Info.plist, scripts, ...) and the readable strings of
//     every binary inside them, against the same "high" rules as the rest of the tree
//     (reverse shells, miners, Keychain theft, Discord/Telegram exfiltration, ...).
//   - the archive itself: entries that would be written outside the target folder
//     ("zip slip"), symlinks that point outside it, encrypted entries that no scanner can
//     look into, entries whose name in the local header differs from the central directory
//     (shows different files to different unzip tools), and archives that can't be read.
//     Nested archives are opened as well.
//
// Used by malware_tree_scan.js (build gate, every tracked archive and kext) and by
// malware-scan.yml (PR scanner, changed archives only). Both pass in their rule list.
//
// Usage as a CLI: node kext_scan.js <file.zip|file> ...   (uses the rules of malware-scan.yml)
'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const MAX_DEPTH = 3;                 // nested archives
const MAX_ENTRY_BYTES = 256 << 20;   // one unpacked file
const MAX_TOTAL_BYTES = 1 << 30;     // everything unpacked from one archive
const MAX_ENTRIES = 50_000;
const MIN_STRING = 6;                // shortest printable run taken from a binary

const MH_OBJECT = 0x1, MH_KEXT_BUNDLE = 0xb;
const MH_TYPES = { 0x1: 'object file', 0x2: 'normal program', 0x3: 'fixed VM library', 0x4: 'core dump',
  0x5: 'preloaded executable', 0x6: 'dynamic library', 0x7: 'dynamic linker', 0x8: 'loadable bundle',
  0x9: 'library stub', 0xa: 'debug symbols', 0xb: 'kernel extension', 0xc: 'fileset' };

// ---- Mach-O --------------------------------------------------------------------------

// Returns null when buf isn't Mach-O, otherwise the file type of every slice.
function machoTypes(buf) {
  if (buf.length < 16) return null;
  const be = buf.readUInt32BE(0);
  if (be === 0xfeedface || be === 0xfeedfacf) return [buf.readUInt32BE(12)];  // big-endian (PowerPC)
  if (be === 0xcefaedfe || be === 0xcffaedfe) return [buf.readUInt32LE(12)];  // little-endian
  if (be === 0xcafebabe || be === 0xcafebabf) {
    const n = buf.readUInt32BE(4);
    if (n === 0 || n > 32) return null;          // also rules out Java class files
    const wide = be === 0xcafebabf, step = wide ? 32 : 20;
    const types = [];
    for (let i = 0; i < n; i++) {
      const o = 8 + i * step;
      if (o + step > buf.length) return ['truncated'];
      const off = wide ? Number(buf.readBigUInt64BE(o + 8)) : buf.readUInt32BE(o + 8);
      const slice = buf.subarray(off, off + 16);
      const t = slice.length >= 16 ? machoTypes(slice) : null;
      types.push(t && t.length === 1 ? t[0] : 'not Mach-O');
    }
    return types;
  }
  return null;
}

const isAppleDouble = buf => buf.length >= 4 && buf.readUInt32BE(0) === 0x00051607;
const isBinary = buf => buf.subarray(0, 8000).includes(0);

// X.kext/Contents/MacOS/<file> (also nested PlugIns), not X.kext.dSYM/...
const KEXT_EXEC = /(^|\/)[^/]+\.kext\/Contents\/MacOS\/[^/]+$/;

function checkKextExecutable(where, buf) {
  if (isAppleDouble(buf)) return null;            // Finder metadata (._name), not code
  const types = machoTypes(buf);
  if (!types) {
    const script = buf.subarray(0, 2).toString() === '#!';
    return {
      what: `is the executable of a kext but ${script ? 'a script' : 'not a Mach-O binary'}, so it can't be a kernel extension`,
      de: `ist die ausführbare Datei einer Kext, aber ${script ? 'ein Skript' : 'keine Mach-O-Datei'} und kann daher keine Kernel-Erweiterung sein`,
    };
  }
  const bad = types.filter(t => t !== MH_KEXT_BUNDLE && t !== MH_OBJECT);
  if (!bad.length) return null;
  const names = [...new Set(bad.map(t => MH_TYPES[t] || String(t)))].join(', ');
  return {
    what: `is the executable of a kext but a ${names}, not a kernel extension - a program disguised as a kext`,
    de: `ist die ausführbare Datei einer Kext, aber keine Kernel-Erweiterung (Mach-O-Typ: ${names}) - ein als Kext getarntes Programm`,
  };
}

// ---- Rules on text and on the strings of binaries --------------------------------------

function textLines(buf) {
  if (!isBinary(buf)) return buf.toString('utf8').split('\n');
  // Printable ASCII runs, like `strings`
  const out = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const c = i < buf.length ? buf[i] : 0;
    const printable = (c >= 0x20 && c < 0x7f) || c === 0x09;
    if (printable) { if (start < 0) start = i; continue; }
    if (start >= 0 && i - start >= MIN_STRING) out.push(buf.toString('latin1', start, i));
    start = -1;
  }
  return out;
}

function matchRules(where, buf, rules, report) {
  const lines = textLines(buf);
  const binary = isBinary(buf);
  for (const rule of rules) {
    if (rule.skipExt && rule.skipExt.test(where)) continue;
    const i = lines.findIndex(l => rule.res.some(re => re.test(l)));
    if (i === -1) continue;
    report({ where, line: binary ? null : i + 1, what: rule.en, de: rule.de, snippet: lines[i].trim().slice(0, 200) });
  }
}

// ---- Zip reader (central directory, stored + deflate) ----------------------------------

function readZip(buf) {
  const minEocd = Math.max(0, buf.length - 0xffff - 22);
  let e = -1;
  for (let i = buf.length - 22; i >= minEocd; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { e = i; break; }
  }
  if (e < 0) throw new Error('no end of central directory record');
  let count = buf.readUInt16LE(e + 10);
  let cdOff = buf.readUInt32LE(e + 16);
  if (count === 0xffff || cdOff === 0xffffffff) {                   // Zip64
    const loc = e - 20;
    if (loc < 0 || buf.readUInt32LE(loc) !== 0x07064b50) throw new Error('broken Zip64 locator');
    const z = Number(buf.readBigUInt64LE(loc + 8));
    if (buf.readUInt32LE(z) !== 0x06064b50) throw new Error('broken Zip64 record');
    count = Number(buf.readBigUInt64LE(z + 32));
    cdOff = Number(buf.readBigUInt64LE(z + 48));
  }
  if (count > MAX_ENTRIES) throw new Error(`${count} entries is more than the ${MAX_ENTRIES} that are checked`);

  const entries = [];
  let p = cdOff;
  for (let n = 0; n < count; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) throw new Error('broken central directory');
    const flags = buf.readUInt16LE(p + 8), method = buf.readUInt16LE(p + 10);
    let csize = buf.readUInt32LE(p + 20), usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32);
    const madeBy = buf.readUInt16LE(p + 4) >> 8, attr = buf.readUInt32LE(p + 38);
    let lho = buf.readUInt32LE(p + 42);
    const nameBuf = buf.subarray(p + 46, p + 46 + nlen);
    const name = nameBuf.toString(flags & 0x800 ? 'utf8' : 'latin1');
    // Zip64 sizes/offset live in extra field 0x0001
    let x = p + 46 + nlen;
    const xend = x + xlen;
    while (x + 4 <= xend) {
      const id = buf.readUInt16LE(x), sz = buf.readUInt16LE(x + 2);
      if (id === 0x0001) {
        let q = x + 4;
        if (usize === 0xffffffff) { usize = Number(buf.readBigUInt64LE(q)); q += 8; }
        if (csize === 0xffffffff) { csize = Number(buf.readBigUInt64LE(q)); q += 8; }
        if (lho === 0xffffffff) { lho = Number(buf.readBigUInt64LE(q)); q += 8; }
      }
      x += 4 + sz;
    }
    const mode = madeBy === 3 ? attr >>> 16 : 0;                    // Unix permissions
    entries.push({ name, nameBuf, flags, method, csize, usize, lho, mode });
    p += 46 + nlen + xlen + clen;
  }
  return entries;
}

function entryData(buf, ent) {
  const o = ent.lho;
  if (o + 30 > buf.length || buf.readUInt32LE(o) !== 0x04034b50) throw new Error('broken local header');
  const nlen = buf.readUInt16LE(o + 26), xlen = buf.readUInt16LE(o + 28);
  const localName = buf.subarray(o + 30, o + 30 + nlen);
  const start = o + 30 + nlen + xlen;
  const raw = buf.subarray(start, start + ent.csize);
  if (raw.length !== ent.csize) throw new Error('entry runs past the end of the archive');
  let data;
  if (ent.method === 0) data = raw;
  else if (ent.method === 8) data = zlib.inflateRawSync(raw, { maxOutputLength: MAX_ENTRY_BYTES });
  else throw new Error(`compression method ${ent.method} isn't supported`);
  return { data, localName };
}

// Where an entry (or a symlink target) would end up relative to the extraction folder.
function escapes(p) {
  if (p.startsWith('/') || p.startsWith('\\') || /^[A-Za-z]:/.test(p)) return true;
  let depth = 0;
  for (const part of p.split(/[/\\]+/)) {
    if (part === '..') { if (--depth < 0) return true; }
    else if (part && part !== '.') depth++;
  }
  return false;
}

// ---- Public API -------------------------------------------------------------------------

const isZip = buf => buf.length >= 4 && buf.readUInt32LE(0) === 0x04034b50;
const S_IFMT = 0o170000, S_IFLNK = 0o120000;

// Findings: { kind: 'kext', where, line (inside a text file, else null), what (English, reads
// after "This file ..."), de (German), snippet (matched text, for rule hits) }.
//
// Scans one archive. `where` is the label for reports ("payloads/Kexts/X.zip"), entries are
// reported as "X.zip!Lilu.kext/Contents/MacOS/Lilu". `onBinary(where, data)` (optional) gets
// every Mach-O inside, e.g. for hash lookups. Returns the findings.
function scanArchive(where, buf, rules, { onBinary, depth = 0 } = {}) {
  const findings = [];
  const report = f => findings.push({ kind: 'kext', ...f });
  let entries;
  try { entries = readZip(buf); } catch (e) {
    report({ where, line: null, what: `is an archive that couldn't be read (${e.message}), so its contents couldn't be checked for malware`,
      de: `ist ein Archiv, das nicht gelesen werden konnte (${e.message}), daher konnte der Inhalt nicht auf Malware geprüft werden` });
    return findings;
  }
  let total = 0;
  for (const ent of entries) {
    const inner = `${where}!${ent.name}`;
    if (escapes(ent.name)) {
      report({ where: inner, line: null, what: 'would be unpacked outside the target folder ("zip slip"), a way to overwrite other files on the Mac',
        de: 'würde außerhalb des Zielordners entpackt ("Zip Slip"), ein Weg, andere Dateien auf dem Mac zu überschreiben' });
      continue;
    }
    if (ent.name.endsWith('/')) continue;
    if (ent.flags & 0x1) {
      report({ where: inner, line: null, what: 'is encrypted, so no scanner can look into it - a common way to slip malware past antivirus checks',
        de: 'ist verschlüsselt, sodass kein Scanner hineinsehen kann - ein üblicher Weg, Malware an Virenscannern vorbeizuschleusen' });
      continue;
    }
    if (ent.usize > MAX_ENTRY_BYTES || total + ent.usize > MAX_TOTAL_BYTES) {
      report({ where: inner, line: null, what: 'unpacks to more data than is checked (possible zip bomb), so it couldn\'t be checked for malware',
        de: 'entpackt mehr Daten als geprüft werden (mögliche Zip-Bombe), daher konnte es nicht auf Malware geprüft werden' });
      break;
    }
    let data, localName;
    try { ({ data, localName } = entryData(buf, ent)); } catch (e) {
      report({ where: inner, line: null, what: `couldn't be unpacked (${e.message}), so it couldn't be checked for malware`,
        de: `konnte nicht entpackt werden (${e.message}), daher konnte es nicht auf Malware geprüft werden` });
      continue;
    }
    total += data.length;
    if (!localName.equals(ent.nameBuf)) {
      const other = localName.toString('latin1').slice(0, 120);
      report({ where: inner, line: null, what: `has a different name in its local header ("${other}"), so different unzip tools would unpack different files`,
        de: `hat im lokalen Header einen anderen Namen ("${other}"), sodass verschiedene Entpacker verschiedene Dateien entpacken würden` });
    }
    if ((ent.mode & S_IFMT) === S_IFLNK) {
      const target = data.toString('utf8');
      const dir = path.posix.dirname(ent.name);
      if (escapes(target) || escapes(path.posix.join(dir, target))) {
        report({ where: inner, line: null, what: `is a symlink to "${target.slice(0, 120)}" outside the archive, which can make an unpacked kext read or overwrite other files`,
          de: `ist ein symbolischer Link auf "${target.slice(0, 120)}" außerhalb des Archivs, über den eine entpackte Kext andere Dateien lesen oder überschreiben kann` });
      }
      continue;
    }
    findings.push(...scanFile(inner, data, rules, { onBinary, depth: depth + 1 }));
  }
  return findings;
}

// Scans one file: a nested archive, a kext executable, any binary (strings) or text file.
function scanFile(where, buf, rules, { onBinary, depth = 0 } = {}) {
  const findings = [];
  const report = f => findings.push({ kind: 'kext', ...f });
  if (isZip(buf)) {
    if (depth <= MAX_DEPTH) return scanArchive(where, buf, rules, { onBinary, depth });
    report({ where, line: null, what: `is an archive nested more than ${MAX_DEPTH} levels deep, so its contents weren't checked`,
      de: `ist ein Archiv, das mehr als ${MAX_DEPTH} Ebenen tief verschachtelt ist, daher wurde der Inhalt nicht geprüft` });
    return findings;
  }
  const name = where.slice(where.lastIndexOf('!') + 1);
  if (KEXT_EXEC.test(name)) {
    const bad = checkKextExecutable(where, buf);
    if (bad) report({ where, line: null, ...bad });
  }
  if (onBinary && machoTypes(buf)) onBinary(where, buf);
  // Text files outside archives are already covered by the callers' own line scan.
  if (depth > 0 || isBinary(buf)) matchRules(where, buf, rules, report);
  return findings;
}

module.exports = { scanArchive, scanFile, machoTypes, isZip };

// ---- CLI ---------------------------------------------------------------------------------

if (require.main === module) {
  const root = process.cwd();
  const src = fs.readFileSync(path.join(root, '.github/workflows/malware-scan.yml'), 'utf8');
  const m = src.match(/\/\/ RULES-START\n([\s\S]*?)\/\/ RULES-END/);
  const rules = new Function(`${m[1]}\nreturn RULES;`)().filter(r => r.sev === 'high');
  let found = 0;
  for (const f of process.argv.slice(2)) {
    for (const x of scanFile(f, fs.readFileSync(f), rules)) {
      found++;
      console.log(`${x.where}${x.line ? ':' + x.line : ''}: ${x.what}${x.snippet ? `\n    ${x.snippet}` : ''}`);
    }
  }
  process.exitCode = found ? 1 : 0;
}
