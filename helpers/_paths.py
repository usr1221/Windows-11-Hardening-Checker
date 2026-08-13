"""Shared paths and CLI plumbing for the policy-set generators.

Everything is resolved relative to the repository root, so the pipeline runs
from any working directory:

    python3 helpers/parse_cis_report.py
    python3 helpers/parse_cis_pdf.py
    python3 helpers/build_policies_cis.py
    python3 helpers/build_policies_vdi.py

Intermediate artefacts land in .cis-build/ (git-ignored); the four files the
audit tool consumes are written to the repository root.
"""
import argparse
import glob
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(REPO, '.cis-build')

# Intermediates
RULES_JSON = os.path.join(WORK, 'cis_rules_raw.json')   # one entry per report rule
GROUPS_JSON = os.path.join(WORK, 'cis_groups.json')     # section number -> group title
PDF_TEXT = os.path.join(WORK, 'cis_pdf.txt')            # extracted benchmark text
PDF_JSON = os.path.join(WORK, 'cis_pdf_reg.json')       # section -> registry mapping

# Deliverables
POLICIES_CIS = os.path.join(REPO, 'Policies-CIS.json')
POLICIES_VDI = os.path.join(REPO, 'Policies-VDI.json')
DECISIONS_CSV = os.path.join(REPO, 'Policies-VDI-Decisions.csv')
POLICIES_EDGE = os.path.join(REPO, 'Policies-Edge.json')
POLICIES_ASD = os.path.join(REPO, 'Policies.json')      # cross-check source


def ensure_work():
    os.makedirs(WORK, exist_ok=True)
    return WORK


def find_one(pattern, what):
    """Locate the single CIS-CAT report / benchmark PDF in the repo root."""
    hits = sorted(glob.glob(os.path.join(REPO, pattern)))
    if not hits:
        raise SystemExit('%s not found (looked for %s in %s)' % (what, pattern, REPO))
    if len(hits) > 1:
        raise SystemExit('more than one %s found - pass the path explicitly:\n  %s'
                         % (what, '\n  '.join(hits)))
    return hits[0]


def parser(description):
    return argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
