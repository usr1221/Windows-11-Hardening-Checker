#!/usr/bin/env python3
r"""Parse a CIS Windows benchmark PDF on its own, without a CIS-CAT report.

The Windows 11 pipeline pairs the PDF with a CIS-CAT HTML report, but CIS-CAT
Lite does not cover Windows Server, so for the Server benchmarks the PDF is the
only input. It carries everything the report did - every recommendation has
the same nine labelled parts:

    Profile Applicability / Description / Rationale / Impact / Audit /
    Remediation / Default Value / References / CIS Controls

Text is extracted with pypdf's *layout* mode. The default mode splits words
("comple tely", "stand -alone") and pads every backslash in a path with a space;
layout mode keeps words and paths intact, which matters because the notes are
carried into the report verbatim.

Line wrapping is repaired per field:

  * registry location - a break after the ':' is inside the value name and is
    joined with no space (LdapEnforceChannelBind|ing); a break inside the key
    path is at a real space (LanMan Print|Services, Session|Manager)
  * Group Policy path - Word only wraps it at spaces, so lines join with one
  * prose             - lines join with a space; a line ending in '-' keeps the
    hyphen and joins with none ("stand-|alone")

Importable (parse_pdf) and runnable on its own to dump the parsed
recommendations for inspection.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths as P

LABELS = ['Profile Applicability', 'Description', 'Rationale', 'Impact', 'Audit',
          'Remediation', 'Default Value', 'References', 'CIS Controls']
LABEL_RE = re.compile(r'^[ \t]*(%s|Additional Information):[ \t]*$' % '|'.join(LABELS), re.M)

# A recommendation heading: section number, title (may wrap), assessment status.
HEAD_RE = re.compile(r'^[ \t]*(\d+(?:\.\d+)+)[ \t]+(\S.*?)\((Automated|Manual)\)[ \t]*$', re.M | re.S)

REG_START_RE = re.compile(r'^[ \t]*(HK(?:LM|CU|U|EY_LOCAL_MACHINE|EY_CURRENT_USER|EY_USERS)\\\S.*)$', re.M)


# ------------------------------------------------------------------ extract --
def extract_text(pdf_path, cache):
    """Layout-mode text, one '===PAGE n===' marker per page, cached on disk."""
    if os.path.exists(cache) and os.path.getmtime(cache) >= os.path.getmtime(pdf_path):
        return open(cache, encoding='utf-8').read()
    try:
        from pypdf import PdfReader
    except ImportError:
        raise SystemExit('pypdf is required to read the benchmark PDF: pip install pypdf')
    print('extracting text from %s (about 30 s) ...' % os.path.basename(pdf_path))
    reader = PdfReader(pdf_path)
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    with open(cache, 'w', encoding='utf-8') as fh:
        for i, page in enumerate(reader.pages):
            fh.write('\n===PAGE %d===\n' % (i + 1))
            fh.write(page.extract_text(extraction_mode='layout') or '')
    return open(cache, encoding='utf-8').read()


def strip_pages(txt):
    """Drop the page markers and the 'Page N' footer each page ends with."""
    txt = re.sub(r'\n===PAGE \d+===\n', '\n', txt)
    txt = re.sub(r'(?m)^[ \t]+Page \d+[ \t]*$', '', txt)
    # Layout mode sometimes pushes a hyphen to the right margin, either mid-word
    # ("last signed                -in") or at the line end ("for non        -").
    txt = re.sub(r'([A-Za-z]) {2,}-(?=[A-Za-z]|[ \t]*$)', r'\1-', txt, flags=re.M)
    return txt


# ------------------------------------------------------------------- joiners --
def join_prose(text):
    lines = [l.strip() for l in text.strip().split('\n')]
    out = ''
    for l in lines:
        if not l:
            out = out.rstrip() + '\n\n' if out else out
            continue
        last_tok = out.rsplit(None, 1)[-1] if out.strip() else ''
        if not out or out.endswith('\n'):
            out += l
        elif out.endswith('-') and not out.endswith(' -'):
            out += l
        elif re.match(r'^-[A-Za-z]', l):
            out += l      # wrapped right before a hyphen: "signed|-in"
        elif '\\' in last_tok and l[:1].islower():
            out += l      # a path wrapped mid-token: "CurrentControlS|et"
        else:
            out += ' ' + l
    # paragraphs -> single spaces (the notes are one line in the report)
    return re.sub(r'\s+', ' ', out).strip()


def join_path(lines):
    """Group Policy path: wrapped at spaces, or either side of a hyphen
    ("Post-|authentication", "signed|-in") - those join with no space."""
    out = ''
    for l in (x.strip() for x in lines):
        if not out:
            out = l
        elif out.endswith('-') or l.startswith('-'):
            out += l
        else:
            out += ' ' + l
    return re.sub(r'\s+', ' ', out).strip()


def join_reg(lines):
    """Registry location: see the module docstring for the rule.

    Value names never contain spaces, so a break after the ':' is always
    mid-token. In the key path Word wraps at a space when it can (LanMan
    Print|Services, Session|Manager) but breaks a long space-free run anywhere
    (Harden|edPaths), and never puts a space straight after a backslash - so a
    continuation that starts lowercase or follows a '\\' is joined with none."""
    out = lines[0].strip()
    for l in lines[1:]:
        l = l.strip()
        if ':' in out or out.endswith(('\\', '-')) or l[:1].islower() or l[:1] in '\\-':
            out += l
        else:
            out += ' ' + l
    out = re.sub(r'\s*\\\s*', lambda _m: '\\', out)            # never a space beside '\'
    out = re.sub(r'\{[^}]*\}', lambda m: re.sub(r'\s+', '', m.group(0)), out)   # GUIDs
    return out


HIVES = [(r'^HKEY_LOCAL_MACHINE\\', 'HKLM\\'), (r'^HKEY_CURRENT_USER\\', 'HKCU\\'),
         (r'^HKEY_USERS\\', 'HKU\\'), (r'^HKU\\\[USER SID\]\\', 'HKCU\\')]


def normalise_hive(path):
    for pat, rep in HIVES:
        path = re.sub(pat, lambda _m: rep, path, flags=re.I)
    return path


# --------------------------------------------------------------------- parse --
def parse_toc_groups(txt):
    """section -> group title, from the table of contents.

    TOC entries wrap and end in a dotted leader plus the page number; the ones
    without an assessment status are the groups."""
    first_body = txt.find('Profile Applicability:')
    toc = txt[:first_body]
    groups = {}
    entry = None
    for raw in toc.split('\n'):
        line = raw.strip()
        m = re.match(r'^(\d+(?:\.\d+)*)\s+(\S.*)$', line)
        if m and not re.match(r'^\d+(?:\.\d+)*\s+\d+$', line):
            entry = [m.group(1), m.group(2)]
        elif entry and line:
            entry[1] += ' ' + line
        else:
            entry = None
            continue
        if re.search(r'(?:\.{2,}|\s)\s*\d+\s*$', entry[1]) or re.search(r'\)\s*\d+$', entry[1]):
            title = re.sub(r'[\s.]*\.{2,}[\s.]*\d+\s*$', '', entry[1])
            title = re.sub(r'\s+\d+$', '', title).strip()
            title = re.sub(r'\s+', ' ', title)
            if not re.search(r'\((?:Automated|Manual)\)', title):
                groups[entry[0]] = title
            entry = None
    return groups


def split_labels(body):
    parts = {}
    marks = list(LABEL_RE.finditer(body))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(body)
        parts.setdefault(m.group(1), body[m.end():end])
    return parts


def parse_regs(audit):
    """Every 'HKLM\\key:Value' in the Audit part, with wrapped lines rejoined."""
    regs = []
    lines = audit.split('\n')
    i = 0
    while i < len(lines):
        m = REG_START_RE.match(lines[i])
        if not m:
            i += 1
            continue
        chunk = [m.group(1)]
        j = i + 1
        while j < len(lines):
            nxt = lines[j].strip()
            if not nxt or REG_START_RE.match(lines[j]):
                break
            if re.match(r'^(Note|Remediation|OR|or|and|Default)\b', nxt):
                break
            # A continuation is a path fragment, never a sentence: one token
            # ("ing", "ePath"), something holding a backslash
            # ("Manager\Kernel:ObCaseInsensitive"), or the tail of a spaced key
            # plus the value name ("Browser protection:DisallowExploit...").
            spaced_tail = (':' not in ''.join(chunk)
                           and re.match(r'^[\w .{}-]+:[\w\\*{}.-]+$', nxt))
            if re.search(r'\s', nxt) and '\\' not in nxt and not spaced_tail:
                break
            chunk.append(nxt)
            j += 1
        loc = join_reg(chunk)
        mm = re.match(r'^(HK[^:]+?)\s*:\s*(\S.*?)\s*$', loc)
        if mm:
            regs.append({'path': normalise_hive(mm.group(1).strip()),
                         'name': mm.group(2).rstrip('.,;').strip()})
        else:
            regs.append({'path': normalise_hive(loc.rstrip(':.').strip()), 'name': ''})
        i = j
    seen, out = set(), []
    for r in regs:
        k = (r['path'].lower(), r['name'].lower())
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def parse_gp_path(remediation):
    lines = remediation.split('\n')
    for i, l in enumerate(lines):
        if re.match(r'^\s*(Computer|User) Configuration\\', l):
            chunk = [l]
            for nxt in lines[i + 1:]:
                if not nxt.strip() or re.match(r'^\s*(Note|Impact)\b', nxt):
                    break
                chunk.append(nxt)
            return join_path(chunk)
    return ''


def parse_pdf(txt):
    """-> (groups, recommendations[])"""
    groups = parse_toc_groups(txt)
    txt = strip_pages(txt)
    first_body = txt.find('Profile Applicability:')

    heads = []
    for m in re.finditer(r'^[ \t]*Profile Applicability:[ \t]*$', txt, re.M):
        win_start = max(0, m.start() - 700)
        win = txt[win_start:m.start()]
        best = None
        # Last heading candidate that runs right up to the anchor.
        for c in reversed([x.start() for x in re.finditer(r'(?m)^[ \t]*\d+(?:\.\d+)+[ \t]', win)]):
            hm = HEAD_RE.match(win, c)
            if hm and not win[hm.end():].strip():
                best = hm
                break
        if best:
            heads.append((win_start + best.start(), best.group(1),
                          re.sub(r'\s+', ' ', best.group(2)).strip(), best.group(3)))
    heads.sort()

    recs = []
    for i, (pos, sec, title, status) in enumerate(heads):
        end = heads[i + 1][0] if i + 1 < len(heads) else len(txt)
        body = txt[pos:end]
        # The last recommendation runs into the appendix.
        cut = re.search(r'(?m)^[ \t]*Appendix:', body)
        if cut:
            body = body[:cut.start()]
        parts = split_labels(body)
        profiles = [re.sub(r'\s+', ' ', p).strip()
                    for p in re.findall(r'•\s*([^\n•]+)', parts.get('Profile Applicability', ''))]
        audit = parts.get('Audit', '')
        flat_audit = re.sub(r'\s+', ' ', audit)
        # "...with a REG_DWORD value of 30 or less, but not 0 HKLM\..." - the
        # phrase ends at the registry location, not reliably at a full stop.
        tm = re.search(r'(REG_\w+)\s+value\b\s*(?:of\s+)?(.*?)\s*(?=HK(?:LM|CU|U|EY_)\w*\\)', flat_audit)
        guid = re.search(r'subcategory\s*:\s*"?\{([0-9a-fA-F-]{36})\}', flat_audit)
        recs.append({
            'section': sec,
            'title': title,
            'status': status,
            'profiles': profiles,
            'description': join_prose(parts.get('Description', '')),
            'rationale': join_prose(parts.get('Rationale', '')),
            'impact': join_prose(parts.get('Impact', '')),
            'audit': join_prose(audit),
            'remediation': join_prose(parts.get('Remediation', '')),
            'default': join_prose(parts.get('Default Value', '')),
            'additional': join_prose(parts.get('Additional Information', '')),
            'gp_path': parse_gp_path(parts.get('Remediation', '')),
            'regs': parse_regs(audit),
            'reg_type': tm.group(1) if tm else '',
            'reg_expect': tm.group(2).strip().rstrip('.:').strip() if tm else '',
            'audit_guid': guid.group(1).lower() if guid else '',
            'missing_labels': [l for l in LABELS if l not in parts],
        })
    return groups, recs


def main():
    ap = P.parser(__doc__)
    ap.add_argument('--pdf', required=True, help='CIS benchmark PDF')
    ap.add_argument('--out', default=None, help='where to write the parsed JSON')
    args = ap.parse_args()
    slug = P.benchmark_slug(args.pdf)
    work = P.work_dir(slug)
    groups, recs = parse_pdf(extract_text(args.pdf, os.path.join(work, 'layout.txt')))
    out = args.out or os.path.join(work, 'recs.json')
    json.dump({'groups': groups, 'recs': recs}, open(out, 'w'), indent=1, ensure_ascii=False)
    print('recommendations:', len(recs), ' groups:', len(groups), ' ->', os.path.relpath(out, P.REPO))


if __name__ == '__main__':
    main()
