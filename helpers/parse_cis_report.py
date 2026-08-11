#!/usr/bin/env python3
"""Step 1 - extract every assessed rule from the CIS-CAT HTML report.

The report's "Assessment Details" area holds one <div class="Rule ..."> per
recommendation, carrying the full (untruncated) description, rationale,
remediation UI path, the OVAL criteria that were evaluated and - for rules that
passed - the registry item that was actually read. The .xlsx export of the same
report truncates the description at ~220 characters, which is why the JSON is
built from the HTML instead.

Writes .cis-build/cis_rules_raw.json and .cis-build/cis_groups.json.
"""
import html as htmlmod
import json
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths as P


def strip_tags(frag):
    frag = re.sub(r'(?is)<(script|style).*?</\1>', ' ', frag)
    frag = re.sub(r'(?i)</(p|div|tr|li|h\d|code)>', ' \n', frag)
    frag = re.sub(r'(?i)<br\s*/?>', ' \n', frag)
    txt = re.sub(r'(?s)<[^>]+>', ' ', frag)
    txt = htmlmod.unescape(txt)
    txt = txt.replace(' ', ' ')
    txt = re.sub(r'[ \t]+', ' ', txt)
    txt = re.sub(r'\s*\n\s*', '\n', txt)
    txt = re.sub(r'\n{2,}', '\n', txt)
    return txt.strip()


def one_line(frag):
    return re.sub(r'\s+', ' ', strip_tags(frag)).strip()


def section_div(block, cls):
    """Inner HTML of the first <div class="cls">, matching nested divs."""
    m = re.search(r'<div class="%s">' % cls, block)
    if not m:
        return None
    i = m.end()
    depth = 1
    for tm in re.finditer(r'<div\b|</div>', block[i:]):
        if tm.group(0) == '</div>':
            depth -= 1
            if depth == 0:
                return block[i:i + tm.start()]
        else:
            depth += 1
    return block[i:]


def parse(report_path):
    raw = open(report_path, encoding='utf-8', errors='replace').read()
    body = raw[raw.index('<div id="assessmentDetailsArea">'):]

    # section number -> group title, used to derive the Category column
    groups = {}
    for m in re.finditer(r'<h2 class="ruleGroupTitle"[^>]*>(.*?)</h2>', body, re.S):
        t = one_line(m.group(1))
        num = t.split(' ', 1)[0]
        if re.match(r'^\d+(\.\d+)*$', num):
            groups[num] = t[len(num):].strip()

    rule_re = re.compile(r'<div id="detail-(d1e\d+)" class="(Rule [^"]*)">')
    marks = [(m.start(), m.group(1), m.group(2)) for m in rule_re.finditer(body)]

    rules = []
    for i, (pos, rid, cls) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(body)
        block = body[pos:end]

        m = re.search(r'<h3 class="ruleTitle" title="([^"]*)">(.*?)</h3>', block, re.S)
        if not m:
            continue
        title = one_line(m.group(2))
        sec = title.split(' ', 1)[0]
        name = title[len(sec):].strip()

        rm = re.search(r'<span class="outcome (\w+) ruleResultArea">([^<]*)</span>', block)
        result = rm.group(2).strip() if rm else ''

        fix = section_div(block, 'fix')
        if fix is None:
            fm = re.search(r'(?s)<div class="(fixtext|remediation)">(.*?)(?=<div id="detail-|<div class="check")', block)
            fix = fm.group(2) if fm else ''

        items = []
        for tbl in re.findall(r'(?s)<table class="evidence" width="100%">(.*?)</table>', block):
            cap = re.search(r'<caption>(.*?)</caption>', tbl)
            cap = one_line(cap.group(1)) if cap else ''
            fields = {}
            for tr in re.findall(r'(?s)<tr[^>]*>(.*?)</tr>', tbl):
                tds = re.findall(r'(?s)<td[^>]*>(.*?)</td>', tr)
                if len(tds) >= 4:
                    fields[one_line(tds[0])] = one_line(tds[3])
            if cap or fields:
                items.append({'caption': cap, 'fields': fields})

        rules.append({
            'id': rid,
            'section': sec,
            'title': name,
            'full_title': title,
            'result': result,
            'igs': re.findall(r'IG\d', cls),
            'classes': cls.strip(),
            'description': strip_tags(section_div(block, 'description') or ''),
            'rationale': strip_tags(section_div(block, 'rationale') or ''),
            'remediation': strip_tags(fix or ''),
            'gp_paths': [one_line(c) for c in re.findall(r'(?s)<code class="code_block">(.*?)</code>', block)],
            'criteria': [one_line(c) for c in
                         re.findall(r'(?s)<td class="bold">Criterion:</td>\s*<td>(.*?)</td>', block)],
            'evidence': items,
        })
    return rules, groups


def main():
    ap = P.parser(__doc__)
    ap.add_argument('--report', default=None, help='CIS-CAT HTML report')
    args = ap.parse_args()

    report = args.report or P.find_one('*CIS_Microsoft_Windows_11*.html', 'CIS-CAT HTML report')
    rules, groups = parse(report)

    P.ensure_work()
    json.dump(rules, open(P.RULES_JSON, 'w'), indent=1)
    json.dump(groups, open(P.GROUPS_JSON, 'w'), indent=1)

    print('report      :', os.path.basename(report))
    print('rules       :', len(rules))
    print('groups      :', len(groups))
    print('with criteria:', sum(1 for r in rules if r['criteria']))
    print('with GP path :', sum(1 for r in rules if r['gp_paths']))
    print('registry evidence:', sum(1 for r in rules
                                    if any(i['caption'] == 'Registry Item' for i in r['evidence'])))


if __name__ == '__main__':
    main()
