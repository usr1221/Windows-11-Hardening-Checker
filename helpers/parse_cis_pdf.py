#!/usr/bin/env python3
r"""Step 2 - extract the registry mapping of every recommendation from the PDF.

The CIS-CAT report does not carry registry paths (it only shows the registry
item for rules that passed), but the benchmark PDF does: each recommendation's
Audit section reads

    This group policy setting is backed by the following registry location
    with a REG_DWORD value of 1.
    HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer:EnableAuthRateLimiter

so the PDF is the authority for RegistryPath, SettingName, ValueType and the
expected value. PDF extraction wraps long paths across lines and hyphenates
GUIDs, both of which are repaired here.

Requires pypdf. Writes .cis-build/cis_pdf.txt (cached) and cis_pdf_reg.json.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths as P

HEAD_RE = re.compile(
    r'(\d+(?:\.\d+)+)\s+((?:\(L\d\)\s*)?(?:Ensure|Configure|Disable|Enable|Create|Set)\b'
    r'[^\n]{0,160}(?:\n[^\n]{0,160}){0,5}?)\((?:Automated|Manual)\)\s*$')


def extract_text(pdf_path, cache):
    if os.path.exists(cache) and os.path.getmtime(cache) >= os.path.getmtime(pdf_path):
        return open(cache, encoding='utf-8', errors='replace').read()
    try:
        from pypdf import PdfReader
    except ImportError:
        raise SystemExit('pypdf is required to read the benchmark PDF: pip install pypdf')
    print('extracting text from %s (this takes a minute) ...' % os.path.basename(pdf_path))
    reader = PdfReader(pdf_path)
    with open(cache, 'w', encoding='utf-8') as fh:
        for i, page in enumerate(reader.pages):
            fh.write('\n===PAGE %d===\n' % (i + 1))
            fh.write(page.extract_text() or '')
    return open(cache, encoding='utf-8', errors='replace').read()


def clean_reg(s):
    s = s.replace('\n', '')
    s = re.sub(r'\s*\\\s*', '\\\\', s)     # "SOFTWARE \Policies \Microsoft" -> joined
    s = re.sub(r'\s{2,}', ' ', s)
    return s.strip()


def find_headings(txt):
    """Every recommendation body starts at its heading, which is immediately
    followed by "Profile Applicability:"."""
    marks = []
    for a in [m.start() for m in re.finditer(r'Profile Applicability\s*:', txt)]:
        base = max(0, a - 900)
        win = txt[base:a]
        # Take the LAST candidate that runs all the way to the anchor, testing
        # start positions right-to-left: otherwise an earlier CIS Controls line
        # ("v7 9.2 Ensure Only Approved Ports ...") swallows the real heading.
        best = None
        for c in reversed([m.start() for m in re.finditer(r'\d+(?:\.\d+)+', win)]):
            m = HEAD_RE.match(win, c)
            if m:
                best = m
                break
        if best:
            marks.append((base + best.start(), best.group(1),
                          re.sub(r'\s+', ' ', best.group(2)).strip()))
    marks.sort()
    return marks


def parse(txt):
    txt = re.sub(r'\n===PAGE \d+===\n', '\n', txt)
    txt = re.sub(r'Page \d+ ', ' ', txt)
    marks = find_headings(txt)

    recs = {}
    for i, (pos, sec, title) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(txt)
        body = txt[pos:end]

        regs = []
        for hm in re.finditer(r'HK(?:LM|CU|U|EY_LOCAL_MACHINE|EY_CURRENT_USER|EY_USERS)\\', body):
            seg = body[hm.start():hm.start() + 500]
            cut = re.search(r'\n\s*(?:Remediation|Note|Default Value|Impact|Audit|References|CIS Controls)\b', seg)
            if cut:
                seg = seg[:cut.start()]
            seg = clean_reg(seg)
            m = re.match(r'^(HK[^:]+?):(\S+)', seg)
            if m:
                regs.append({'path': m.group(1).strip(), 'name': m.group(2).rstrip('.,;')})
            else:
                m2 = re.match(r'^(HK\S+)', seg)
                if m2:
                    regs.append({'path': m2.group(1).rstrip(':'), 'name': ''})

        tm = re.search(r'(REG_\w+)\s+value of\s+([^\n]{0,80}?)\s*\.', re.sub(r'\s+', ' ', body))

        seen, ded = set(), []
        for r in regs:
            k = (r['path'].lower(), r['name'].lower())
            if k not in seen:
                seen.add(k)
                ded.append(r)

        if sec not in recs or (not recs[sec]['regs'] and ded):
            recs[sec] = {
                'section': sec,
                'title': title,
                'regs': ded,
                'reg_type': tm.group(1) if tm else '',
                'reg_expect': tm.group(2) if tm else '',
                'body': re.sub(r'\s+', ' ', body),
            }
    return recs


def main():
    ap = P.parser(__doc__)
    ap.add_argument('--pdf', default=None, help='CIS benchmark PDF')
    args = ap.parse_args()

    pdf = args.pdf or P.find_one('CIS_Microsoft_Windows_11*.pdf', 'CIS benchmark PDF')
    P.ensure_work()
    recs = parse(extract_text(pdf, P.PDF_TEXT))
    json.dump(recs, open(P.PDF_JSON, 'w'), indent=1)

    print('recommendations   :', len(recs))
    print('with registry path:', sum(1 for v in recs.values() if v['regs']))

    if os.path.exists(P.RULES_JSON):
        rules = json.load(open(P.RULES_JSON))
        missing = [r['section'] for r in rules if r['section'] not in recs]
        noreg = [r['section'] for r in rules if r['section'] in recs and not recs[r['section']]['regs']]
        print('report rules unmatched in PDF:', len(missing), missing[:10])
        # Expected: account policy, user rights, audit subcategories and the
        # three local-account checks are not registry-backed.
        print('report rules with no registry mapping:', len(noreg))


if __name__ == '__main__':
    main()
