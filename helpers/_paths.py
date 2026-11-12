"""Shared paths and CLI plumbing for the policy-set generators.

Everything is resolved relative to the repository root, so the pipeline runs
from any working directory:

    python3 helpers/parse_cis_report.py
    python3 helpers/parse_cis_pdf.py
    python3 helpers/build_policies_cis.py
    python3 helpers/build_policies_vdi.py
    python3 helpers/build_policies_cis_server.py   # Windows Server, PDF only
    python3 helpers/build_policies_edge.py

Repository layout:

    sources/     inputs - benchmark PDFs, CIS-CAT reports, Edge baseline files
    .cis-build/  intermediates (git-ignored; per-benchmark subfolders for the
                 Server PDFs)
    policies/    the policy sets the audit tool consumes
"""
import argparse
import glob
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(REPO, '.cis-build')
SOURCES = os.path.join(REPO, 'sources')
POLICIES = os.path.join(REPO, 'policies')

# Intermediates
RULES_JSON = os.path.join(WORK, 'cis_rules_raw.json')   # one entry per report rule
GROUPS_JSON = os.path.join(WORK, 'cis_groups.json')     # section number -> group title
PDF_TEXT = os.path.join(WORK, 'cis_pdf.txt')            # extracted benchmark text
PDF_JSON = os.path.join(WORK, 'cis_pdf_reg.json')       # section -> registry mapping

# Deliverables
POLICIES_CIS = os.path.join(POLICIES, 'Policies-CIS.json')
POLICIES_VDI = os.path.join(POLICIES, 'Policies-VDI.json')
DECISIONS_CSV = os.path.join(POLICIES, 'Policies-VDI-Decisions.csv')
POLICIES_EDGE = os.path.join(POLICIES, 'Policies-Edge.json')
POLICIES_ASD = os.path.join(POLICIES, 'Policies.json')      # cross-check source


def ensure_work():
    os.makedirs(WORK, exist_ok=True)
    return WORK


def benchmark_slug(pdf_path):
    """'CIS_Microsoft_Windows_Server_2022_Benchmark_v5.1.0.pdf' -> 'Server2022'."""
    base = os.path.basename(pdf_path)
    m = re.search(r'Windows_Server_(\d{4})', base)
    if m:
        return 'Server' + m.group(1)
    m = re.search(r'Windows_(\d+)_', base)
    return 'Win' + m.group(1) if m else re.sub(r'\W+', '_', os.path.splitext(base)[0])


def work_dir(slug):
    """Per-benchmark intermediates, e.g. .cis-build/server2022/."""
    d = os.path.join(WORK, slug.lower())
    os.makedirs(d, exist_ok=True)
    return d


def policies_server(slug, profile):
    """'Server2022', 'MS' -> policies/Policies-CIS-Server2022-MS.json"""
    return os.path.join(POLICIES, 'Policies-CIS-%s-%s.json' % (slug, profile))


def find_all(pattern):
    """Source documents matching pattern: sources/ first, then the repository
    root (so a freshly downloaded file dropped at the top level still works)."""
    return sorted(glob.glob(os.path.join(SOURCES, pattern))) or sorted(glob.glob(os.path.join(REPO, pattern)))


def find_one(pattern, what):
    """Locate the single CIS-CAT report / benchmark PDF / baseline file."""
    hits = find_all(pattern)
    if not hits:
        raise SystemExit('%s not found (looked for %s in %s and %s)' % (what, pattern, SOURCES, REPO))
    if len(hits) > 1:
        raise SystemExit('more than one %s found - pass the path explicitly:\n  %s'
                         % (what, '\n  '.join(hits)))
    return hits[0]


def parser(description):
    return argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
