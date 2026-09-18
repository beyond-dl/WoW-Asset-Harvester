#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================================
 WoW Asset Harvester - chunk-accurate dependency extractor for WotLK (3.3.5a)
=====================================================================================
Version 1.4.3

  - ADT parser reads MCLY via the MCNK header offset (0x1C) instead of relying
    on a sequential sub-chunk walk. On WotLK ADTs, MCNR carries 13 bytes of
    padding that its declared chunk size does not count, which desyncs the
    sequential walk and silently drops every chunk after MCNR (MCLY included).
    The sequential walk is retained as a last-resort fallback.

  - Diagnostics now report which base the MCLY offset used: chunk-relative
    (offset - 8), payload-relative (offset), or sequential fallback.

  - Paths ending in ".bl" are still treated as model bugs (a real Blizzard M2
    typo). Logged separately, not copied, not reported missing.

  - Short report harvest_found_dbc.txt with only DBC-derived files (ground
    effects + skyboxes) plus model path-bug warnings.

  - All prior behaviour from 1.4.2 preserved.
=====================================================================================
"""

import os
import re
import sys
import struct
import shutil
import threading
import traceback
from collections import defaultdict

APP_NAME = "WoW Asset Harvester"
APP_VERSION = "1.4.3"

try:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    SCRIPT_DIR = os.getcwd()

DEFAULT_SOURCE_DIR = ""
DEFAULT_ADT_DIR = ""
DEFAULT_DBC_DIR = ""
DEFAULT_OUTPUT_DIR = ""

MODEL_EXTS = ('.m2', '.mdx')
COMPANION_EXTS = ('.skin', '.anim', '.phys', '.bone', '.skel')

KNOWN_ASSET_EXTS = {
    '.m2', '.mdx', '.mdl', '.wmo', '.blp', '.skin', '.anim', '.phys',
    '.bone', '.skel', '.adt', '.dbc', '.wdt', '.wdl', '.lit', '.wlw',
    '.wlq', '.wlm', '.wav', '.mp3', '.tga', '.jpg', '.jpeg', '.avi',
    '.m3', '.xml',
}

DEFAULT_THRESHOLD_GROUND_EFFECT_DOODAD  = 798
DEFAULT_THRESHOLD_GROUND_EFFECT_TEXTURE = 72973
DEFAULT_THRESHOLD_LIGHT_SKYBOX          = 148


# =====================================================================================
# PATH HELPERS
# =====================================================================================

def norm(p):
    return p.strip().replace('/', '\\').lower().strip('\\')


def wow_basename(p):
    return norm(p).rsplit('\\', 1)[-1]


def mdx_to_m2(p):
    low = p.lower()
    if low.endswith('.mdx') or low.endswith('.mdl'):
        return p[:-4] + '.m2'
    return p


def sanitize_asset_path(raw):
    if not raw:
        return None
    s = norm(raw)
    s = s.lstrip('\\./ ')
    s = re.sub(r'^[0-9]+(?:\.[0-9]+)*\\', '', s)
    s = s.lstrip('\\./ ')
    if len(s) < 5 or '.' not in s:
        return None
    if any(ch in s for ch in ('\n', '\r', '\t', '*', '?', '"', '<', '>', '|')):
        return None
    return mdx_to_m2(s)


def extension_of(p):
    b = wow_basename(p)
    if '.' not in b:
        return ''
    return '.' + b.rsplit('.', 1)[-1]


# =====================================================================================
# CHUNK READER
# =====================================================================================

def read_chunks(data):
    chunks = defaultdict(list)
    order = []
    offset = 0
    n = len(data)

    while offset + 8 <= n:
        raw_magic = data[offset:offset + 4]
        if not all(48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122 for b in raw_magic):
            break
        magic = raw_magic[::-1].decode('ascii')
        size = struct.unpack_from('<I', data, offset + 4)[0]
        start = offset + 8
        end = start + size
        if end > n:
            chunks[magic].append(data[start:n])
            order.append(magic)
            break
        chunks[magic].append(data[start:end])
        order.append(magic)
        offset = end
    return chunks, order


def cstring_at(blob, offset):
    if not blob or offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b'\x00', offset)
    if end == -1:
        end = len(blob)
    return blob[offset:end].decode('utf-8', errors='ignore').strip()


def split_cstrings(blob):
    out = []
    for piece in blob.split(b'\x00'):
        if piece:
            s = piece.decode('utf-8', errors='ignore').strip()
            if s:
                out.append(s)
    return out


# =====================================================================================
# ADT PARSER
# =====================================================================================

MCNK_HEADER_SIZE = 128
MCLY_ENTRY_SIZE = 16
MCLY_EFFECT_ID_OFFSET = 0x0C
MCNK_OFF_EFFECTID = 0x7C
MCNK_OFF_MCLY = 0x1C


def _blank_adt_diag():
    return {
        'n_mcnk': 0,
        'n_mcnk_too_small': 0,
        'n_mcnk_with_mcly': 0,
        'n_mcly_records': 0,
        'n_mcly_nonzero_eid': 0,
        'n_mcnk_nonzero_7c': 0,
        'sub_magics': defaultdict(int),
        'sample_7c_values': [],
        'sample_mcly_eids': [],
        'sample_mcly_texture_ids': [],
        'mcly_bases': defaultdict(int),
    }


def parse_adt(data):
    """Returns (textures, m2_models, wmo_objects, ground_effect_ids, diag)."""
    chunks, _ = read_chunks(data)
    textures, models, wmos = set(), set(), set()
    effect_ids = set()
    diag = _blank_adt_diag()

    for blob in chunks.get('MTEX', []):
        textures.update(split_cstrings(blob))
    for blob in chunks.get('MMDX', []):
        models.update(split_cstrings(blob))
    for blob in chunks.get('MWMO', []):
        wmos.update(split_cstrings(blob))

    for mcnk in chunks.get('MCNK', []):
        diag['n_mcnk'] += 1
        if len(mcnk) <= MCNK_HEADER_SIZE:
            diag['n_mcnk_too_small'] += 1
            continue

        ofs_mcly = struct.unpack_from('<I', mcnk, MCNK_OFF_MCLY)[0]
        tile_eid = struct.unpack_from('<I', mcnk, MCNK_OFF_EFFECTID)[0]

        if len(diag['sample_7c_values']) < 8:
            diag['sample_7c_values'].append(tile_eid)
        if tile_eid:
            diag['n_mcnk_nonzero_7c'] += 1
            effect_ids.add(tile_eid)

        sub, _ = read_chunks(mcnk[MCNK_HEADER_SIZE:])
        for magic in sub.keys():
            diag['sub_magics'][magic] += 1

        mcly_payload = None
        mcly_base_used = None
        for base_delta, base_name in ((-8, 'chunk'), (0, 'payload')):
            mcly_pos = ofs_mcly + base_delta
            if mcly_pos <= 0 or mcly_pos + 8 > len(mcnk):
                continue
            if mcnk[mcly_pos:mcly_pos + 4] != b'YLCM':
                continue
            size = struct.unpack_from('<I', mcnk, mcly_pos + 4)[0]
            payload_start = mcly_pos + 8
            payload_end = payload_start + size
            if payload_end > len(mcnk):
                payload_end = len(mcnk)
            mcly_payload = mcnk[payload_start:payload_end]
            mcly_base_used = base_name
            break

        if mcly_payload is None and sub.get('MCLY'):
            mcly_payload = b''.join(sub['MCLY'])
            mcly_base_used = 'sequential'

        if mcly_payload is None:
            continue

        diag['n_mcnk_with_mcly'] += 1
        diag['mcly_bases'][mcly_base_used] += 1

        for i in range(len(mcly_payload) // MCLY_ENTRY_SIZE):
            entry = mcly_payload[i * MCLY_ENTRY_SIZE:(i + 1) * MCLY_ENTRY_SIZE]
            if len(entry) < MCLY_ENTRY_SIZE:
                break
            diag['n_mcly_records'] += 1
            textid = struct.unpack_from('<I', entry, 0)[0]
            eid = struct.unpack_from('<I', entry, MCLY_EFFECT_ID_OFFSET)[0]
            if len(diag['sample_mcly_eids']) < 8:
                diag['sample_mcly_eids'].append(eid)
                diag['sample_mcly_texture_ids'].append(textid)
            if eid:
                diag['n_mcly_nonzero_eid'] += 1
                effect_ids.add(eid)

    return textures, models, wmos, effect_ids, diag


# =====================================================================================
# WMO ROOT PARSER
# =====================================================================================

MOMT_SIZE = 64
MODD_SIZE = 40
MOMT_TEXTURE_OFFSETS = (0x0C, 0x18, 0x24)


def parse_wmo_root(data):
    chunks, order = read_chunks(data)

    res = {
        'textures': set(),
        'doodads': set(),
        'skybox': None,
        'n_groups': 0,
        'n_doodads': 0,
        'chunks': order,
        'is_root': 'MOHD' in chunks,
    }

    if chunks.get('MOHD'):
        h = chunks['MOHD'][0]
        if len(h) >= 0x18:
            res['n_groups'] = struct.unpack_from('<I', h, 0x04)[0]
            res['n_doodads'] = struct.unpack_from('<I', h, 0x14)[0]

    motx = b''.join(chunks.get('MOTX', []))
    modn = b''.join(chunks.get('MODN', []))

    for blob in chunks.get('MOMT', []):
        for i in range(len(blob) // MOMT_SIZE):
            entry = blob[i * MOMT_SIZE:(i + 1) * MOMT_SIZE]
            for off_pos in MOMT_TEXTURE_OFFSETS:
                tex_off = struct.unpack_from('<I', entry, off_pos)[0]
                if tex_off == 0:
                    continue
                name = cstring_at(motx, tex_off)
                if name and '.' in name:
                    res['textures'].add(name)

    for s in split_cstrings(motx):
        if s.lower().endswith('.blp'):
            res['textures'].add(s)

    for blob in chunks.get('MODD', []):
        for i in range(len(blob) // MODD_SIZE):
            entry = blob[i * MODD_SIZE:(i + 1) * MODD_SIZE]
            if len(entry) < 4:
                continue
            name_off = struct.unpack_from('<I', entry, 0)[0] & 0x00FFFFFF
            name = cstring_at(modn, name_off)
            if name and '.' in name:
                res['doodads'].add(name)

    for s in split_cstrings(modn):
        if s.lower().endswith(MODEL_EXTS):
            res['doodads'].add(s)

    if chunks.get('MOSB'):
        sky = cstring_at(b''.join(chunks['MOSB']), 0)
        if sky and '.' in sky:
            res['skybox'] = sky

    return res


def wmo_group_names(root_rel_path, n_groups):
    base = root_rel_path[:-4] if root_rel_path.lower().endswith('.wmo') else root_rel_path
    return [f"{base}_{i:03d}.wmo" for i in range(n_groups)]


def is_wmo_group_name(name):
    return bool(re.search(r'_\d{3}\.wmo$', name.lower()))


# =====================================================================================
# M2 PARSER
# =====================================================================================

M2_TEXTURE_RECORD = 16


def parse_m2(data):
    res = {'textures': set(), 'n_skins': 0, 'version': 0, 'ok': False}

    if len(data) < 0x60:
        return res

    base = 0
    magic = data[0:4]
    if magic == b'MD21':
        base = 8
        if len(data) < base + 0x60:
            return res
        magic = data[base:base + 4]

    if magic != b'MD20':
        return res

    version = struct.unpack_from('<I', data, base + 0x04)[0]
    res['version'] = version
    pre_wotlk = version < 264

    try:
        p = base + 0x2C
        if pre_wotlk:
            p += 8
        p += 24
        n_skins = struct.unpack_from('<I', data, p)[0]
        p += 4
        if pre_wotlk:
            p += 4
        p += 8
        n_textures = struct.unpack_from('<I', data, p)[0]
        ofs_textures = struct.unpack_from('<I', data, p + 4)[0]
    except struct.error:
        return res

    if n_skins > 64 or n_textures > 4096:
        return res

    res['n_skins'] = n_skins
    res['ok'] = True

    tex_base = base + ofs_textures
    for i in range(n_textures):
        rec = tex_base + i * M2_TEXTURE_RECORD
        if rec + M2_TEXTURE_RECORD > len(data):
            break
        tex_type = struct.unpack_from('<I', data, rec)[0]
        len_name = struct.unpack_from('<I', data, rec + 0x08)[0]
        ofs_name = struct.unpack_from('<I', data, rec + 0x0C)[0]

        if tex_type != 0:
            continue
        if len_name <= 1 or ofs_name == 0:
            continue

        start = base + ofs_name
        end = start + len_name
        if end > len(data):
            continue
        name = data[start:end].split(b'\x00')[0].decode('utf-8', errors='ignore').strip()
        if name and '.' in name:
            res['textures'].add(name)

    return res


# =====================================================================================
# DBC PARSER
# =====================================================================================

DBC_HEADER_SIZE = 20


def parse_dbc(data):
    if len(data) < DBC_HEADER_SIZE or data[0:4] != b'WDBC':
        return None, None
    record_count, field_count, record_size, string_size = struct.unpack_from('<IIII', data, 4)
    if field_count == 0 or record_size == 0 or record_size < field_count * 4:
        return None, None
    body_start = DBC_HEADER_SIZE
    body_end = body_start + record_count * record_size
    if body_end > len(data):
        return None, None
    strings = data[body_end:body_end + string_size]
    records = []
    for i in range(record_count):
        off = body_start + i * record_size
        records.append(struct.unpack_from('<' + 'I' * field_count, data, off))
    return records, strings


def parse_ground_effect_doodad(data, return_column=False):
    records, strings = parse_dbc(data)
    if not records:
        return ({}, None) if return_column else {}
    field_count = len(records[0])
    best_col, best_hits = None, 0
    for col in range(1, field_count):
        hits = 0
        for rec in records:
            s = cstring_at(strings, rec[col])
            if s and s.lower().endswith(MODEL_EXTS):
                hits += 1
        if hits > best_hits:
            best_col, best_hits = col, hits
    if best_col is None or best_hits == 0:
        return ({}, None) if return_column else {}
    out = {}
    for rec in records:
        s = cstring_at(strings, rec[best_col])
        if s and s.lower().endswith(MODEL_EXTS):
            out[rec[0]] = s
    return (out, best_col) if return_column else out


def parse_ground_effect_texture(data, known_doodad_ids):
    records, _ = parse_dbc(data)
    if not records:
        return {}
    out = {}
    for rec in records:
        refs = [v for v in rec[1:] if v in known_doodad_ids]
        if refs:
            out[rec[0]] = refs
    return out


def _find_dbc(dbc_dir, filename):
    for root, dirs, files in os.walk(dbc_dir):
        for f in files:
            if f.lower() == filename.lower():
                return os.path.join(root, f)
    return None


def parse_light_dbc(data):
    records, _ = parse_dbc(data)
    if not records:
        return {}
    out = {}
    for rec in records:
        params = [v for v in rec[7:15] if v]
        if params:
            out[rec[0]] = params
    return out


def parse_light_params_dbc(data):
    records, _ = parse_dbc(data)
    if not records:
        return {}
    out = {}
    for rec in records:
        if len(rec) < 3:
            continue
        sid = rec[2]
        if sid:
            out[rec[0]] = sid
    return out


def parse_light_skybox_dbc(data):
    records, strings = parse_dbc(data)
    if not records:
        return {}
    out = {}
    for rec in records:
        if len(rec) < 2:
            continue
        s = cstring_at(strings, rec[1])
        if s and '.' in s:
            out[rec[0]] = s
    return out


# =====================================================================================
# SOURCE INDEX
# =====================================================================================

class SourceIndex:

    def __init__(self):
        self.by_rel = {}
        self.by_full = {}
        self.by_name = defaultdict(list)
        self.by_dir = defaultdict(list)
        self.root_norm = ""

    def build(self, source_dir, log):
        if not os.path.isdir(source_dir):
            raise FileNotFoundError(f"Source folder not found: {source_dir}")
        log(f"Indexing source: {source_dir}")
        self.root_norm = norm(source_dir)
        count = 0
        for root, dirs, files in os.walk(source_dir):
            rel_dir = norm(root)
            if rel_dir.startswith(self.root_norm):
                rel_dir = rel_dir[len(self.root_norm):].strip('\\')
            bucket = self.by_dir[rel_dir]
            for f in files:
                low = f.lower()
                full = os.path.join(root, f)
                rel = f"{rel_dir}\\{low}" if rel_dir else low
                self.by_rel[rel] = full
                self.by_full[full] = rel
                self.by_name[low].append(full)
                bucket.append((low, full))
                count += 1
        log(f"  files: {count} | unique names: {len(self.by_name)} | folders: {len(self.by_dir)}")
        return count

    def resolve(self, rel_path):
        key = norm(rel_path)
        hit = self.by_rel.get(key)
        if hit:
            return hit, 'rel'
        suffix = '\\' + key
        for rel, full in self.by_rel.items():
            if rel.endswith(suffix):
                return full, 'suffix'
        cands = self.by_name.get(wow_basename(key))
        if cands:
            return cands[0], 'name'
        return None, None

    def candidates_in_folders(self, bare_name):
        out = []
        for full in self.by_name.get(bare_name, []):
            rel = self.by_full.get(full, '')
            if '\\' in rel:
                out.append(rel)
        return sorted(out)

    def siblings_with_prefix(self, rel_path, suffixes):
        key = norm(rel_path)
        rel_dir = key.rsplit('\\', 1)[0] if '\\' in key else ''
        stem = os.path.splitext(wow_basename(key))[0]
        out = []
        for fname, full in self.by_dir.get(rel_dir, []):
            if fname.startswith(stem) and fname.endswith(suffixes):
                rel = f"{rel_dir}\\{fname}" if rel_dir else fname
                out.append((rel, full))
        return out


# =====================================================================================
# HARVESTER
# =====================================================================================

class Harvester:

    def __init__(self, index, log, fetch_texture_variants=False, thresholds=None):
        self.index = index
        self.log = log
        self.fetch_texture_variants = fetch_texture_variants
        self.thresholds = thresholds or {}

        self.queue = []
        self.seen = set()
        self.resolved = {}
        self.missing = {}
        self.tree_log = []
        self.stats = defaultdict(int)
        self.ground_effect_related = set()

        self.dbcref_custom_pulled = set()
        self.dbcref_base_resolved = set()
        self.dbcref_base_in_client = set()
        self.light_related = set()

        self.path_bugs = defaultdict(list)

    def _resolve_relative_hint(self, cleaned):
        if not cleaned or '\\' in cleaned:
            return cleaned, None
        if self.index.by_rel.get(cleaned):
            return cleaned, None
        candidates = self.index.candidates_in_folders(cleaned)
        if not candidates:
            return cleaned, None
        return candidates[0], candidates[0]

    def _note_possible_path_bug(self, raw_path, origin):
        if not raw_path:
            return False
        ext = extension_of(raw_path)
        if not ext:
            return False
        if ext in KNOWN_ASSET_EXTS:
            return False
        self.path_bugs[raw_path].append(origin)
        self.stats['skipped_path_bug'] += 1
        return True

    def add(self, raw_path, kind, origin):
        if self._note_possible_path_bug(raw_path, origin):
            return
        cleaned = sanitize_asset_path(raw_path)
        if not cleaned:
            self.stats['discarded_as_junk'] += 1
            return
        cleaned, adopted = self._resolve_relative_hint(cleaned)
        if adopted:
            self.tree_log.append(f"  [path] '{raw_path}' -> '{adopted}'  ({origin})")
        if kind == 'ground_doodad' or origin in self.ground_effect_related:
            self.ground_effect_related.add(cleaned)
        if cleaned in self.seen:
            return
        self.seen.add(cleaned)
        self.queue.append((cleaned, kind, origin))

    def add_dbcref(self, raw_path, kind, origin, row_id, threshold_key):
        if self._note_possible_path_bug(raw_path, origin):
            return
        cleaned = sanitize_asset_path(raw_path)
        if not cleaned:
            self.stats['discarded_as_junk'] += 1
            return
        cleaned, adopted = self._resolve_relative_hint(cleaned)
        if adopted:
            self.tree_log.append(
                f"  [DBC:path] bare name '{raw_path}' adopted source folder "
                f"-> '{adopted}'  ({origin})"
            )
        if kind == 'ground_doodad' or origin in self.ground_effect_related:
            self.ground_effect_related.add(cleaned)
        threshold = self.thresholds.get(threshold_key, 0)
        is_custom = row_id > threshold
        tag = 'CUSTOM' if is_custom else 'BASE'
        self.tree_log.append(
            f"  [DBC:{tag}] {threshold_key} row {row_id} -> {cleaned}  ({origin})"
        )
        src, _ = self.index.resolve(cleaned)
        if src:
            if is_custom:
                self.dbcref_custom_pulled.add(cleaned)
            else:
                self.dbcref_base_resolved.add(cleaned)
            if cleaned in self.seen:
                return
            self.seen.add(cleaned)
            self.queue.append((cleaned, kind, origin))
            return
        if is_custom:
            self.missing.setdefault(cleaned, []).append(
                f"{origin} [custom row {row_id}, source incomplete]"
            )
            self.stats[f'MISSING_{kind}'] += 1
            if threshold_key == 'ground_effect_doodad':
                self.ground_effect_related.add(cleaned)
            if threshold_key == 'light_skybox':
                self.light_related.add(cleaned)
        else:
            self.dbcref_base_in_client.add(cleaned)
            self.stats['base_dbcref_present_in_client'] += 1

    def run(self):
        processed = 0
        while self.queue:
            rel, kind, origin = self.queue.pop(0)
            processed += 1
            self._process(rel, kind, origin)
        return processed

    def _process(self, rel, kind, origin):
        src, how = self.index.resolve(rel)
        if not src:
            self.missing.setdefault(rel, []).append(origin)
            self.stats[f'MISSING_{kind}'] += 1
            if rel in self.ground_effect_related:
                self.stats['MISSING_ground_effect_related'] += 1
            return
        self.resolved[rel] = (src, how)
        self.stats[f'found_{kind}'] += 1
        if how != 'rel':
            self.stats[f'found_via_{how}'] += 1
        if isinstance(origin, str) and origin.startswith('LightSkybox'):
            self.light_related.add(rel)
        low = rel.lower()
        if low.endswith('.wmo') and not is_wmo_group_name(low):
            self._expand_wmo(rel, src)
        elif low.endswith('.m2'):
            self._expand_m2(rel, src)
        elif low.endswith('.blp') and self.fetch_texture_variants:
            stem = rel[:-4]
            if re.search(r'_[shn]$', stem, flags=re.IGNORECASE):
                return
            for suf in ('_s', '_h', '_n'):
                variant = stem + suf + '.blp'
                v_src, _ = self.index.resolve(variant)
                if v_src:
                    self.add(variant, 'texture_variant', rel)

    def _expand_wmo(self, rel, src):
        try:
            with open(src, 'rb') as f:
                info = parse_wmo_root(f.read())
        except Exception as e:
            self.tree_log.append(f"[!] Failed to read WMO {rel}: {e}")
            return
        self.tree_log.append(
            f"WMO {rel}  groups={info['n_groups']} doodads(MOHD)={info['n_doodads']} "
            f"textures={len(info['textures'])} doodad_names={len(info['doodads'])} "
            f"chunks={','.join(sorted(set(info['chunks'])))}"
        )
        if info['n_doodads'] > 0 and not info['doodads']:
            self.tree_log.append(
                f"    [!] MOHD declares {info['n_doodads']} doodads but no names were "
                f"recovered (MODN/MODD missing or damaged)"
            )
        for g in wmo_group_names(rel, info['n_groups']):
            self.add(g, 'wmo_group', rel)
        for t in info['textures']:
            self.add(t, 'texture', rel)
        for d in info['doodads']:
            self.add(d, 'model', rel)
        if info['skybox']:
            self.add(info['skybox'], 'model', rel)

    def _expand_m2(self, rel, src):
        try:
            with open(src, 'rb') as f:
                info = parse_m2(f.read())
        except Exception as e:
            self.tree_log.append(f"[!] Failed to read M2 {rel}: {e}")
            return
        if not info['ok']:
            self.tree_log.append(f"[!] M2 {rel}: header could not be parsed")
            return
        for t in info['textures']:
            self.add(t, 'texture', rel)
        sibs = self.index.siblings_with_prefix(rel, COMPANION_EXTS)
        n_anim = 0
        for sib_rel, sib_src in sibs:
            if sib_rel not in self.seen:
                self.seen.add(sib_rel)
                self.resolved[sib_rel] = (sib_src, 'sibling')
                self.stats['found_companion'] += 1
                if sib_rel.endswith('.anim'):
                    n_anim += 1
        n_skin = sum(1 for r, _ in sibs if r.endswith('.skin'))
        if info['n_skins'] > n_skin:
            self.tree_log.append(
                f"[!] M2 {rel}: header declares {info['n_skins']} skin profiles but only "
                f"{n_skin} .skin files exist - the model may fail to render"
            )
        if n_anim:
            self.tree_log.append(f"    M2 {rel}: pulled {n_anim} external .anim file(s)")

    def copy_all(self, out_dir):
        copied = skipped = failed = 0
        for rel, (src, how) in sorted(self.resolved.items()):
            dst = os.path.join(out_dir, rel.replace('\\', os.sep))
            try:
                if os.path.exists(dst) and os.path.getsize(dst) == os.path.getsize(src):
                    skipped += 1
                    continue
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
                copied += 1
            except Exception as e:
                self.log(f"  [!] Copy failed for {rel}: {e}")
                failed += 1
        return copied, skipped, failed


# =====================================================================================
# PIPELINE
# =====================================================================================

def _merge_adt_diag(agg, diag):
    agg['n_mcnk'] += diag['n_mcnk']
    agg['n_mcnk_too_small'] += diag['n_mcnk_too_small']
    agg['n_mcnk_with_mcly'] += diag['n_mcnk_with_mcly']
    agg['n_mcly_records'] += diag['n_mcly_records']
    agg['n_mcly_nonzero_eid'] += diag['n_mcly_nonzero_eid']
    agg['n_mcnk_nonzero_7c'] += diag['n_mcnk_nonzero_7c']
    for k, v in diag['sub_magics'].items():
        agg['sub_magics'][k] += v
    for k, v in diag.get('mcly_bases', {}).items():
        agg['mcly_bases'][k] += v
    if len(agg['sample_7c_values']) < 16:
        agg['sample_7c_values'].extend(
            diag['sample_7c_values'][: 16 - len(agg['sample_7c_values'])]
        )
    if len(agg['sample_mcly_eids']) < 16:
        agg['sample_mcly_eids'].extend(
            diag['sample_mcly_eids'][: 16 - len(agg['sample_mcly_eids'])]
        )
        agg['sample_mcly_texture_ids'].extend(
            diag['sample_mcly_texture_ids'][
                : 16 - len(agg['sample_mcly_texture_ids'])
            ]
        )


def collect_adt(harvester, adt_dir, log):
    adt_files = []
    if os.path.isdir(adt_dir):
        for root, dirs, files in os.walk(adt_dir):
            for f in files:
                if f.lower().endswith('.adt'):
                    adt_files.append(os.path.join(root, f))
    adt_files = sorted(set(adt_files))

    log(f"\nADT files found: {len(adt_files)}")
    if not adt_files:
        log(f"  !!! Place your .adt files in: {adt_dir}")
        return 0, set()

    tex = mdl = wmo = 0
    effect_ids = set()
    empty = 0
    diag = _blank_adt_diag()

    for path in adt_files:
        try:
            with open(path, 'rb') as f:
                data = f.read()
            textures, models, wmos, eids, tile_diag = parse_adt(data)
        except Exception as e:
            log(f"  [!] {os.path.basename(path)}: {e}")
            empty += 1
            continue
        if not (textures or models or wmos):
            empty += 1
        _merge_adt_diag(diag, tile_diag)
        origin = f"ADT:{os.path.basename(path)}"
        for t in textures:
            harvester.add(t, 'texture', origin)
            tex += 1
        for m in models:
            harvester.add(m, 'model', origin)
            mdl += 1
        for w in wmos:
            harvester.add(w, 'wmo', origin)
            wmo += 1
        effect_ids |= eids

    log(f"  references -> textures: {tex}, models: {mdl}, WMOs: {wmo}")
    if empty:
        log(f"  !!! ADTs with no MTEX/MMDX/MWMO at all: {empty}")

    log("")
    log("ADT ground-effect diagnostics (aggregated over all tiles):")
    log(f"  MCNK chunks seen               : {diag['n_mcnk']}")
    log(f"  MCNK too small to hold a header: {diag['n_mcnk_too_small']}")
    log(f"  MCNK with MCLY sub-chunk       : {diag['n_mcnk_with_mcly']}")
    if diag['mcly_bases']:
        bases_str = ', '.join(f"{k}={v}" for k, v in sorted(diag['mcly_bases'].items()))
        log(f"  MCLY resolved via offset base  : {bases_str}")
    log(f"  MCLY layer records total       : {diag['n_mcly_records']}")
    log(f"  MCLY records with effectId != 0: {diag['n_mcly_nonzero_eid']}")
    log(f"  MCNK with header effectId != 0 : {diag['n_mcnk_nonzero_7c']}")
    log(f"  unique ground effect IDs found : {len(effect_ids)}")

    sub_summary = ', '.join(
        f"{m}={n}" for m, n in sorted(diag['sub_magics'].items())
    ) or "(none)"
    log(f"  sub-chunk magics seen in MCNK  : {sub_summary}")

    if diag['sample_7c_values']:
        log(f"  sample MCNK+0x7C values        : {diag['sample_7c_values']}")
    if diag['sample_mcly_eids']:
        pairs = [f"tex={t} eid={e}" for t, e in
                 zip(diag['sample_mcly_texture_ids'], diag['sample_mcly_eids'])]
        log(f"  sample MCLY (textureId,effectId): {pairs}")

    if effect_ids:
        log(f"  -> precise mode: only the {len(effect_ids)} effect IDs above will be expanded")
    else:
        log("  -> nothing in the ADTs carries a ground effect ID. This is not a "
            "bug in the harvester - it means either the map has no painted "
            "ground effects, or the ADT writer stored them elsewhere. The DBC "
            "step below will use safe fallback mode.")

    return len(adt_files), effect_ids


def collect_ground_effects(harvester, dbc_dir, effect_ids, log):
    log("\nGround effects (DBC):")
    if not os.path.isdir(dbc_dir):
        log(f"  DBC folder not found, skipping: {dbc_dir}")
        return 0
    doodad_file = _find_dbc(dbc_dir, 'GroundEffectDoodad.dbc')
    texture_file = _find_dbc(dbc_dir, 'GroundEffectTexture.dbc')
    if not doodad_file or not texture_file:
        log("  Skipped - both DBCs are required.")
        log(f"    GroundEffectDoodad.dbc : {'found' if doodad_file else 'MISSING'}")
        log(f"    GroundEffectTexture.dbc: {'found' if texture_file else 'MISSING'}")
        return 0
    try:
        with open(doodad_file, 'rb') as f:
            doodads, doodad_col = parse_ground_effect_doodad(f.read(), return_column=True)
        with open(texture_file, 'rb') as f:
            textures = parse_ground_effect_texture(f.read(), set(doodads.keys()))
    except Exception as e:
        log(f"  [!] Failed to parse ground effect DBCs: {e}")
        return 0

    th_doodad  = harvester.thresholds.get('ground_effect_doodad', 0)
    th_texture = harvester.thresholds.get('ground_effect_texture', 0)

    log(f"  GroundEffectDoodad: model-path column detected at index {doodad_col}, "
        f"{len(doodads)} rows resolved (base threshold: {th_doodad})")
    log(f"  GroundEffectTexture rows referencing them: {len(textures)} "
        f"(base threshold: {th_texture})")

    if doodads:
        log("  Sample doodad rows (sanity-check these look like real model paths):")
        for row_id, path in list(doodads.items())[:5]:
            tag = 'BASE' if row_id <= th_doodad else 'CUSTOM'
            log(f"    id={row_id} [{tag}] -> {path}")

    added = 0
    if effect_ids:
        unmatched = 0
        for eid in sorted(effect_ids):
            refs = textures.get(eid)
            if not refs:
                unmatched += 1
                continue
            for doodad_id in refs:
                model = doodads.get(doodad_id)
                if model:
                    harvester.add_dbcref(
                        model, 'ground_doodad', f"GroundEffect:{eid}",
                        row_id=doodad_id, threshold_key='ground_effect_doodad'
                    )
                    added += 1
        log(f"  mode: PRECISE (driven by ADT ground effect IDs)")
        log(f"  effect IDs matched: {len(effect_ids) - unmatched} of {len(effect_ids)}")
        log(f"  doodad models queued: {added}")
        if unmatched:
            log(f"  ({unmatched} effect IDs used by terrain are not in the DBC - "
                f"your client may use a different base; raise the threshold if so)")
    else:
        log("  mode: FALLBACK (no ADT ground effect IDs available)")
        log("  Pulling every CUSTOM doodad row (id > threshold). This is safe - "
            "nothing the map might use is skipped - but it is not selective: if "
            "the map only paints a few of your custom rows, all of them are "
            "still queued. To make this selective, the ADT must expose ground "
            "effect IDs in MCLY or at MCNK+0x7C.")
        custom_rows = [(rid, p) for rid, p in doodads.items() if rid > th_doodad]
        log(f"  custom doodad rows (id > {th_doodad}): {len(custom_rows)}")
        for row_id, model in sorted(custom_rows):
            harvester.add_dbcref(
                model, 'ground_doodad', f"GroundEffectCustom:{row_id}",
                row_id=row_id, threshold_key='ground_effect_doodad'
            )
            added += 1
        log(f"  custom doodad models queued: {added}")
    return added


def collect_lights(harvester, dbc_dir, log):
    log("\nLights / skyboxes (DBC):")
    if not os.path.isdir(dbc_dir):
        log(f"  DBC folder not found, skipping: {dbc_dir}")
        return 0

    light_path     = _find_dbc(dbc_dir, 'Light.dbc')
    params_path    = _find_dbc(dbc_dir, 'LightParams.dbc')
    skybox_path    = _find_dbc(dbc_dir, 'LightSkybox.dbc')
    intband_path   = _find_dbc(dbc_dir, 'LightIntBand.dbc')
    floatband_path = _find_dbc(dbc_dir, 'LightFloatBand.dbc')

    log(f"  Light.dbc          : {'found' if light_path else 'MISSING'}")
    log(f"  LightParams.dbc    : {'found' if params_path else 'MISSING'}")
    log(f"  LightSkybox.dbc    : {'found' if skybox_path else 'MISSING'}")
    log(f"  LightIntBand.dbc   : {'found' if intband_path else 'MISSING (colors, not files)'}")
    log(f"  LightFloatBand.dbc : {'found' if floatband_path else 'MISSING (floats, not files)'}")

    if not skybox_path:
        log("  No LightSkybox.dbc - cannot pull skybox models.")
        return 0

    try:
        with open(skybox_path, 'rb') as f:
            skyboxes = parse_light_skybox_dbc(f.read())
    except Exception as e:
        log(f"  [!] Failed to parse LightSkybox.dbc: {e}")
        return 0

    th_skybox = harvester.thresholds.get('light_skybox', 0)
    log(f"  LightSkybox rows with a model path: {len(skyboxes)} "
        f"(base threshold: {th_skybox})")

    referenced_skybox_ids = set()
    if light_path and params_path:
        try:
            with open(light_path, 'rb') as f:
                lights = parse_light_dbc(f.read())
            with open(params_path, 'rb') as f:
                params = parse_light_params_dbc(f.read())
        except Exception as e:
            log(f"  [!] Failed to parse Light/LightParams: {e}")
            lights, params = {}, {}
        log(f"  Light.dbc rows: {len(lights)} | "
            f"LightParams rows with skybox: {len(params)}")
        for _lid, param_ids in lights.items():
            for pid in param_ids:
                sid = params.get(pid)
                if sid:
                    referenced_skybox_ids.add(sid)
        log(f"  Skybox IDs referenced by Light.dbc chain: {len(referenced_skybox_ids)}")

    queued = 0
    if referenced_skybox_ids:
        custom_referenced = sorted(
            sid for sid in referenced_skybox_ids
            if sid > th_skybox and sid in skyboxes
        )
        log(f"  Custom referenced skyboxes (id > {th_skybox}): {len(custom_referenced)}")
        for sid in custom_referenced:
            harvester.add_dbcref(
                skyboxes[sid], 'model', f"LightSkybox:{sid}",
                row_id=sid, threshold_key='light_skybox'
            )
            queued += 1
        log(f"  skybox models queued: {queued}")
    if queued == 0:
        log("  No referenced custom skyboxes resolved - falling back to pulling "
            "every CUSTOM skybox row (id > threshold). Base rows are never bulk-pulled.")
        custom_rows = [(sid, m) for sid, m in skyboxes.items() if sid > th_skybox]
        log(f"  custom skybox rows (id > {th_skybox}): {len(custom_rows)}")
        for sid, model in sorted(custom_rows):
            harvester.add_dbcref(
                model, 'model', f"LightSkyboxCustom:{sid}",
                row_id=sid, threshold_key='light_skybox'
            )
            queued += 1
        log(f"  custom skybox models queued (fallback): {queued}")

    if intband_path:
        try:
            with open(intband_path, 'rb') as f:
                band_records, _ = parse_dbc(f.read())
            if band_records:
                log(f"  LightIntBand rows total: {len(band_records)} (color data, not files)")
        except Exception as e:
            log(f"  [!] LightIntBand parse: {e}")
    if floatband_path:
        try:
            with open(floatband_path, 'rb') as f:
                band_records, _ = parse_dbc(f.read())
            if band_records:
                log(f"  LightFloatBand rows total: {len(band_records)} (float data, not files)")
        except Exception as e:
            log(f"  [!] LightFloatBand parse: {e}")
    return queued


def write_reports(h, report_dir):
    os.makedirs(report_dir, exist_ok=True)
    found_path = os.path.join(report_dir, "harvest_found.txt")
    missing_path = os.path.join(report_dir, "harvest_missing.txt")
    tree_path = os.path.join(report_dir, "harvest_tree.txt")
    dbc_path = os.path.join(report_dir, "harvest_found_dbc.txt")

    with open(found_path, 'w', encoding='utf-8') as f:
        f.write(f"# Resolved and copied: {len(h.resolved)}\n")
        for rel, (src, how) in sorted(h.resolved.items()):
            f.write(f"{rel}\t[{how}]\t{src}\n")

    with open(missing_path, 'w', encoding='utf-8') as f:
        f.write(f"# Not found in the source folder: {len(h.missing)}\n")
        f.write("# Format: path, then what referenced it\n")
        f.write("# Model-side path bugs (.bl etc.) are NOT listed here - see harvest_found_dbc.txt\n\n")
        for rel, origins in sorted(h.missing.items()):
            f.write(f"{rel}\n")
            for o in sorted(set(origins))[:6]:
                f.write(f"      <- {o}\n")

    with open(tree_path, 'w', encoding='utf-8') as f:
        f.write("# WMO / M2 parse tree\n\n")
        f.write("\n".join(h.tree_log))

    with open(dbc_path, 'w', encoding='utf-8') as f:
        f.write("# DBC-derived files (ground effects + skyboxes)\n")
        f.write("# This is the short list - the full copy log is in harvest_found.txt\n\n")

        f.write(f"# Custom ground-effect doodads pulled: {len(h.dbcref_custom_pulled)}\n")
        gef = sorted(r for r in h.dbcref_custom_pulled if r in h.ground_effect_related)
        for r in gef:
            f.write(f"  {r}\n")
        if not gef:
            f.write("  (none)\n")

        f.write(f"\n# Base ground-effect doodads present in source: "
                f"{len(h.dbcref_base_resolved)}\n")
        for r in sorted(h.dbcref_base_resolved):
            f.write(f"  {r}\n")
        if not h.dbcref_base_resolved:
            f.write("  (none)\n")

        f.write(f"\n# Base ground-effect doodads assumed present in client: "
                f"{len(h.dbcref_base_in_client)}\n")
        f.write("  (these were referenced by ADT but absent from source; the "
                "3.3.5a client already ships them, so this is expected)\n")

        f.write(f"\n# Custom skybox models pulled: "
                f"{len([r for r in h.resolved if r in h.light_related])}\n")
        for r in sorted(r for r in h.resolved if r in h.light_related):
            f.write(f"  {r}\n")

        f.write(f"\n# Model-side path bugs (model references an extension that "
                f"does not exist on disk)\n")
        f.write("# These are bugs in the original M2/WMO data, not missing files. "
                "Do NOT copy or rename anything - the client follows the model "
                "literally, so the only proper fix is editing the model itself.\n")
        if h.path_bugs:
            for bad, origins in sorted(h.path_bugs.items()):
                f.write(f"  {bad}\n")
                for o in sorted(set(origins))[:6]:
                    f.write(f"      <- {o}\n")
        else:
            f.write("  (none detected)\n")

    return found_path, missing_path, tree_path, dbc_path


def run_harvest(source_dir, adt_dir, dbc_dir, output_dir,
                fetch_texture_variants=False, log=print, report_dir=None,
                thresholds=None):
    log("=" * 74)
    log(f" {APP_NAME} {APP_VERSION}")
    log("=" * 74)

    index = SourceIndex()
    index.build(source_dir, log)

    os.makedirs(output_dir, exist_ok=True)
    h = Harvester(index, log, fetch_texture_variants, thresholds=thresholds)

    def log_and_keep(msg):
        log(msg)
        h.tree_log.append(str(msg))

    n_adt, effect_ids = collect_adt(h, adt_dir, log_and_keep)
    if not n_adt:
        log("\nNothing to do - no ADT files.")
        return h

    collect_ground_effects(h, dbc_dir, effect_ids, log_and_keep)
    collect_lights(h, dbc_dir, log_and_keep)

    log("\nWalking dependency tree (WMO -> doodads -> textures -> ...)")
    processed = h.run()
    log(f"  unique references processed: {processed}")

    log("\nCopying to output...")
    copied, skipped, failed = h.copy_all(output_dir)

    log("\n" + "=" * 74)
    log(" SUMMARY")
    log("=" * 74)
    for k in sorted(h.stats):
        log(f"  {k}: {h.stats[k]}")

    log(f"\n  DBC references (base vs custom):")
    log(f"    custom files pulled         : {len(h.dbcref_custom_pulled)}")
    log(f"    base files pulled           : {len(h.dbcref_base_resolved)}")
    log(f"    base files present in client: {len(h.dbcref_base_in_client)} "
        f"(referenced by ADT but absent from source - expected)")

    log(f"\n  Newly copied files : {copied}")
    log(f"  Already present    : {skipped}")
    log(f"  Copy errors        : {failed}")
    log(f"  Missing in source  : {len(h.missing)}")
    log(f"  Model path bugs    : {len(h.path_bugs)} (see harvest_found_dbc.txt)")

    reports = write_reports(h, report_dir or SCRIPT_DIR)
    log("\n  Reports:")
    for r in reports:
        log(f"    {r}")

    if h.missing:
        log("\n  First missing entries (full list in harvest_missing.txt):")
        for rel in sorted(h.missing)[:20]:
            log(f"    {rel}")

    ground_missing = sorted(r for r in h.missing if r in h.ground_effect_related)
    if ground_missing:
        log_and_keep(f"\n  !!! {len(ground_missing)} missing file(s) trace back to a ground effect "
                     f"doodad (grass/shrub) - this is almost certainly your checkerboard textures:")
        for rel in ground_missing[:20]:
            log_and_keep(f"    {rel}")
        if len(ground_missing) > 20:
            log_and_keep(f"    ... and {len(ground_missing) - 20} more")
    elif h.ground_effect_related:
        log_and_keep(f"\n  Ground effect doodads: {len(h.ground_effect_related)} files traced, "
                     f"all resolved via path lookup.")
        for rel in sorted(h.ground_effect_related):
            log_and_keep(f"    {rel}")

    light_missing = sorted(r for r in h.missing if r in h.light_related)
    if light_missing:
        log_and_keep(f"\n  !!! {len(light_missing)} missing file(s) trace back to a "
                     f"custom skybox row:")
        for rel in light_missing[:20]:
            log_and_keep(f"    {rel}")
        if len(light_missing) > 20:
            log_and_keep(f"    ... and {len(light_missing) - 20} more")

    log("\n=== DONE ===")
    return h


# =====================================================================================
# GUI
# =====================================================================================

def launch_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    import queue as queue_mod

    root = tk.Tk()
    root.title(f"{APP_NAME} {APP_VERSION}")
    root.geometry("920x780")
    root.minsize(820, 640)

    log_queue = queue_mod.Queue()
    worker = {'thread': None}

    paths = {
        'source': tk.StringVar(value=DEFAULT_SOURCE_DIR),
        'adt': tk.StringVar(value=DEFAULT_ADT_DIR),
        'dbc': tk.StringVar(value=DEFAULT_DBC_DIR),
        'output': tk.StringVar(value=DEFAULT_OUTPUT_DIR),
    }
    variants_var = tk.BooleanVar(value=False)
    thresholds = {
        'ground_effect_doodad':  tk.StringVar(value=str(DEFAULT_THRESHOLD_GROUND_EFFECT_DOODAD)),
        'ground_effect_texture': tk.StringVar(value=str(DEFAULT_THRESHOLD_GROUND_EFFECT_TEXTURE)),
        'light_skybox':          tk.StringVar(value=str(DEFAULT_THRESHOLD_LIGHT_SKYBOX)),
    }

    main = ttk.Frame(root, padding=12)
    main.pack(fill='both', expand=True)

    ttk.Label(
        main,
        text="Pick your folders and press Run. Only the assets your ADT tiles "
             "actually reference are copied.",
        wraplength=880, justify='left'
    ).pack(anchor='w', pady=(0, 10))

    rows = ttk.Frame(main)
    rows.pack(fill='x')
    rows.columnconfigure(1, weight=1)

    def add_row(r, label, key, hint):
        ttk.Label(rows, text=label, width=24).grid(row=r * 2, column=0, sticky='w', pady=(6, 0))
        ttk.Entry(rows, textvariable=paths[key]).grid(row=r * 2, column=1, sticky='ew', padx=6, pady=(6, 0))

        def browse():
            start = paths[key].get()
            initial = start if os.path.isdir(start) else SCRIPT_DIR
            chosen = filedialog.askdirectory(title=label, initialdir=initial)
            if chosen:
                paths[key].set(os.path.normpath(chosen))

        ttk.Button(rows, text="Browse...", command=browse, width=11).grid(row=r * 2, column=2, pady=(6, 0))
        ttk.Label(rows, text=hint, foreground="#666").grid(row=r * 2 + 1, column=1, sticky='w', padx=6)

    add_row(0, "Source (extracted MPQ)", 'source', "The full patch you extract FROM.")
    add_row(1, "ADT folder", 'adt', "Your map's .adt tiles - these drive everything.")
    add_row(2, "DBC folder (optional)", 'dbc', "GroundEffectDoodad/Texture + Light/Params/Skybox DBCs.")
    add_row(3, "Output folder", 'output', "Where the trimmed asset set is written.")

    opts = ttk.Frame(main)
    opts.pack(fill='x', pady=(12, 6))
    ttk.Checkbutton(
        opts,
        text="Also pull _s / _h / _n texture variants (rarely needed on 3.3.5, adds a lot of size)",
        variable=variants_var
    ).pack(anchor='w')

    thr_frame = ttk.LabelFrame(
        main,
        text="DBC ID thresholds (base vs custom) - rows with id <= threshold are "
             "treated as stock 3.3.5a and skipped if absent from source")
    thr_frame.pack(fill='x', pady=(4, 6))
    thr_frame.columnconfigure(1, weight=1)

    def add_thr_row(r, label, key):
        ttk.Label(thr_frame, text=label, width=32).grid(row=r, column=0, sticky='w', padx=6, pady=2)
        ttk.Entry(thr_frame, textvariable=thresholds[key], width=12).grid(row=r, column=1, sticky='w', padx=6, pady=2)
        ttk.Label(thr_frame, foreground="#666",
                  text="rows with id > this value are pulled as custom").grid(
            row=r, column=2, sticky='w', padx=6, pady=2)

    add_thr_row(0, "GroundEffectDoodad max base id",  'ground_effect_doodad')
    add_thr_row(1, "GroundEffectTexture max base id", 'ground_effect_texture')
    add_thr_row(2, "LightSkybox max base id",         'light_skybox')

    buttons = ttk.Frame(main)
    buttons.pack(fill='x', pady=(6, 8))

    run_btn = ttk.Button(buttons, text="Run", width=16)
    run_btn.pack(side='left')

    def open_output():
        target = paths['output'].get()
        if not os.path.isdir(target):
            messagebox.showinfo(APP_NAME, "The output folder does not exist yet.")
            return
        try:
            if sys.platform.startswith('win'):
                os.startfile(target)
            elif sys.platform == 'darwin':
                os.system(f'open "{target}"')
            else:
                os.system(f'xdg-open "{target}"')
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Could not open the folder:\n{e}")

    ttk.Button(buttons, text="Open output folder", command=open_output).pack(side='left', padx=8)

    status = ttk.Label(buttons, text="Idle", foreground="#444")
    status.pack(side='right')

    log_frame = ttk.Frame(main)
    log_frame.pack(fill='both', expand=True, pady=(4, 0))

    log_text = tk.Text(log_frame, wrap='none', height=18,
                       background="#1e1e1e", foreground="#d4d4d4",
                       insertbackground="#d4d4d4", font=("Consolas", 9))
    yscroll = ttk.Scrollbar(log_frame, orient='vertical', command=log_text.yview)
    xscroll = ttk.Scrollbar(log_frame, orient='horizontal', command=log_text.xview)
    log_text.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
    log_text.grid(row=0, column=0, sticky='nsew')
    yscroll.grid(row=0, column=1, sticky='ns')
    xscroll.grid(row=1, column=0, sticky='ew')
    log_frame.rowconfigure(0, weight=1)
    log_frame.columnconfigure(0, weight=1)

    def gui_log(msg):
        log_queue.put(str(msg))

    def drain():
        try:
            while True:
                line = log_queue.get_nowait()
                log_text.insert('end', line + "\n")
                log_text.see('end')
        except queue_mod.Empty:
            pass
        root.after(80, drain)

    def on_run():
        if worker['thread'] and worker['thread'].is_alive():
            return
        source = paths['source'].get().strip()
        adt = paths['adt'].get().strip()
        dbc = paths['dbc'].get().strip()
        output = paths['output'].get().strip()

        if not os.path.isdir(source):
            messagebox.showerror(APP_NAME, f"Source folder does not exist:\n{source}")
            return
        if not os.path.isdir(adt):
            messagebox.showerror(APP_NAME, f"ADT folder does not exist:\n{adt}")
            return
        if not output:
            messagebox.showerror(APP_NAME, "Please choose an output folder.")
            return
        if norm(output) == norm(source):
            messagebox.showerror(APP_NAME, "The output folder must not be the source folder.")
            return

        try:
            thr_values = {k: int(v.get().strip() or 0) for k, v in thresholds.items()}
        except ValueError:
            messagebox.showerror(APP_NAME, "DBC thresholds must be integers.")
            return

        log_text.delete('1.0', 'end')
        run_btn.configure(state='disabled')
        status.configure(text="Running...", foreground="#0a7")

        def work():
            try:
                run_harvest(source, adt, dbc, output,
                            fetch_texture_variants=variants_var.get(),
                            log=gui_log,
                            report_dir=os.path.dirname(output.rstrip('\\/')) or SCRIPT_DIR,
                            thresholds=thr_values)
            except Exception:
                gui_log("\n=== ERROR ===")
                for line in traceback.format_exc().splitlines():
                    gui_log(line)

        worker['thread'] = threading.Thread(target=work, daemon=True)
        worker['thread'].start()

        def poll():
            if worker['thread'].is_alive():
                root.after(200, poll)
            else:
                run_btn.configure(state='normal')
                status.configure(text="Finished", foreground="#0a7")

        root.after(200, poll)

    run_btn.configure(command=on_run)
    drain()
    root.mainloop()


# =====================================================================================
# ENTRY POINT
# =====================================================================================

def main():
    default_thresholds = {
        'ground_effect_doodad':  DEFAULT_THRESHOLD_GROUND_EFFECT_DOODAD,
        'ground_effect_texture': DEFAULT_THRESHOLD_GROUND_EFFECT_TEXTURE,
        'light_skybox':          DEFAULT_THRESHOLD_LIGHT_SKYBOX,
    }

    if '--nogui' in sys.argv:
        run_harvest(DEFAULT_SOURCE_DIR, DEFAULT_ADT_DIR, DEFAULT_DBC_DIR,
                    DEFAULT_OUTPUT_DIR, log=print, thresholds=default_thresholds)
        input("\nPress Enter to close...")
        return

    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("tkinter is not available, falling back to console mode.")
        run_harvest(DEFAULT_SOURCE_DIR, DEFAULT_ADT_DIR, DEFAULT_DBC_DIR,
                    DEFAULT_OUTPUT_DIR, log=print, thresholds=default_thresholds)
        input("\nPress Enter to close...")
        return

    launch_gui()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        input("\nPress Enter to close...")
