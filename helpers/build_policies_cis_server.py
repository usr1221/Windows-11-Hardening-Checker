#!/usr/bin/env python3
r"""Build Policies-CIS-Server<year>-{MS,DC}.json from a CIS Windows Server benchmark PDF.

    python3 helpers/build_policies_cis_server.py                 # every Server PDF in sources/, both profiles
    python3 helpers/build_policies_cis_server.py --pdf X.pdf     # one benchmark
    python3 helpers/build_policies_cis_server.py --profile DC    # one profile

Two Level 1 profiles are built per benchmark, one file each:

  MS  Level 1 - Member Server       -> policies/Policies-CIS-Server2022-MS.json
  DC  Level 1 - Domain Controller   -> policies/Policies-CIS-Server2022-DC.json

A recommendation is included when its Profile Applicability lists that
profile, so "(MS only)" items land only in the MS file and "(DC only)" items
only in the DC file. Level 2 and Next Generation recommendations are left out.

There is no CIS-CAT report for Windows Server (CIS-CAT Lite does not cover it),
so the PDF is the only input - see parse_cis_server_pdf.py. Sources, in order
of authority:

  * the Audit section    - registry location, REG_* type, expected value, and
                           the auditpol subcategory GUID
  * the title            - user-right principals, audit flags, account-policy
                           values, and the direction of a bare number
                           ("32,768 or greater" when the Audit text says 32768)
  * the tables below     - keyed by the setting name CIS quotes in the title,
                           never by section number: the numbering differs
                           between benchmarks (2.2.33 is "Increase scheduling
                           priority" in Server 2022 and "Impersonate a client"
                           in Server 2019)

Values that are written out by hand here (the remotely accessible registry
path lists) are verified against the benchmark text on every run, and an audit
GUID or user-right constant is cross-checked against policies/Policies-CIS.json. A
warning means the benchmark and this script disagree - read it, don't silence it.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths as P
from _cis_common import (TYPE_MAP, PRINCIPAL_SID, principals_from_title, priority_for, parse_expect,
                         category_for, ordered, ONLY_RE)
from parse_cis_server_pdf import extract_text, parse_pdf

# key -> (Profile Applicability text, short label used in Notes)
PROFILES = {
    'MS': ('Level 1 - Member Server', 'L1 Member Server'),
    'DC': ('Level 1 - Domain Controller', 'L1 Domain Controller'),
}

# ------------------------------------------------------------------ curated --
# secedit [System Access] keys. The value is read from the title, in the units
# secedit exports (days / minutes / count).
SECEDIT = {
    'enforce password history': 'PasswordHistorySize',
    'maximum password age': 'MaximumPasswordAge',
    'minimum password age': 'MinimumPasswordAge',
    'minimum password length': 'MinimumPasswordLength',
    'password must meet complexity requirements': 'PasswordComplexity',
    'store passwords using reversible encryption': 'ClearTextPassword',
    'account lockout duration': 'LockoutDuration',
    'account lockout threshold': 'LockoutBadCount',
    'allow administrator account lockout': 'AllowAdministratorLockout',
    'reset account lockout counter after': 'ResetLockoutCount',
    'network access: allow anonymous sid/name translation': 'LSAAnonymousNameLookup',
    'network security: force logoff when logon hours expire': 'ForceLogoffWhenHourExpire',
}

# Built-in local accounts (RID:Property), evaluated with Get-LocalUser.
LOCALUSER = {
    'accounts: administrator account status': ('500:Enabled', 'False', 'eq'),
    'accounts: guest account status': ('501:Enabled', 'False', 'eq'),
    'accounts: rename administrator account': ('500:Name', 'Administrator', 'ne'),
    'accounts: rename guest account': ('501:Name', 'Guest', 'ne'),
}

# User right display name -> privilege constant (the secedit [Privilege Rights] key).
USER_RIGHTS = {
    'access credential manager as a trusted caller': 'SeTrustedCredManAccessPrivilege',
    'access this computer from the network': 'SeNetworkLogonRight',
    'act as part of the operating system': 'SeTcbPrivilege',
    'add workstations to domain': 'SeMachineAccountPrivilege',
    'adjust memory quotas for a process': 'SeIncreaseQuotaPrivilege',
    'allow log on locally': 'SeInteractiveLogonRight',
    'allow log on through remote desktop services': 'SeRemoteInteractiveLogonRight',
    'back up files and directories': 'SeBackupPrivilege',
    'bypass traverse checking': 'SeChangeNotifyPrivilege',
    'change the system time': 'SeSystemtimePrivilege',
    'change the time zone': 'SeTimeZonePrivilege',
    'create a pagefile': 'SeCreatePagefilePrivilege',
    'create a token object': 'SeCreateTokenPrivilege',
    'create global objects': 'SeCreateGlobalPrivilege',
    'create permanent shared objects': 'SeCreatePermanentPrivilege',
    'create symbolic links': 'SeCreateSymbolicLinkPrivilege',
    'debug programs': 'SeDebugPrivilege',
    'deny access to this computer from the network': 'SeDenyNetworkLogonRight',
    'deny log on as a batch job': 'SeDenyBatchLogonRight',
    'deny log on as a service': 'SeDenyServiceLogonRight',
    'deny log on locally': 'SeDenyInteractiveLogonRight',
    'deny log on through remote desktop services': 'SeDenyRemoteInteractiveLogonRight',
    'enable computer and user accounts to be trusted for delegation': 'SeEnableDelegationPrivilege',
    'force shutdown from a remote system': 'SeRemoteShutdownPrivilege',
    'generate security audits': 'SeAuditPrivilege',
    'impersonate a client after authentication': 'SeImpersonatePrivilege',
    'increase a process working set': 'SeIncreaseWorkingSetPrivilege',
    'increase scheduling priority': 'SeIncreaseBasePriorityPrivilege',
    'load and unload device drivers': 'SeLoadDriverPrivilege',
    'lock pages in memory': 'SeLockMemoryPrivilege',
    'log on as a batch job': 'SeBatchLogonRight',
    'log on as a service': 'SeServiceLogonRight',
    'manage auditing and security log': 'SeSecurityPrivilege',
    'modify an object label': 'SeRelabelPrivilege',
    'modify firmware environment values': 'SeSystemEnvironmentPrivilege',
    'obtain an impersonation token for another user in the same session': 'SeDelegateSessionUserImpersonatePrivilege',
    'perform volume maintenance tasks': 'SeManageVolumePrivilege',
    'profile single process': 'SeProfileSingleProcessPrivilege',
    'profile system performance': 'SeSystemProfilePrivilege',
    'remove computer from docking station': 'SeUndockPrivilege',
    'replace a process level token': 'SeAssignPrimaryTokenPrivilege',
    'restore files and directories': 'SeRestorePrivilege',
    'shut down the system': 'SeShutdownPrivilege',
    'synchronize directory service data': 'SeSyncAgentPrivilege',
    'take ownership of files or other objects': 'SeTakeOwnershipPrivilege',
}

ALLOWED_EXACT_PATHS = [
    'System\\CurrentControlSet\\Control\\ProductOptions',
    'System\\CurrentControlSet\\Control\\Server Applications',
    'Software\\Microsoft\\Windows NT\\CurrentVersion',
]
ALLOWED_PATHS = [
    'System\\CurrentControlSet\\Control\\Print\\Printers',
    'System\\CurrentControlSet\\Services\\Eventlog',
    'Software\\Microsoft\\OLAP Server',
    'Software\\Microsoft\\Windows NT\\CurrentVersion\\Print',
    'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
    'System\\CurrentControlSet\\Control\\ContentIndex',
    'System\\CurrentControlSet\\Control\\Terminal Server',
    'System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig',
    'System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration',
    'Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib',
    'System\\CurrentControlSet\\Services\\SysmonLog',
]

# Registry checks whose expected value cannot be read straight off the Audit
# text. Keyed by 'parentkey\valuename' or 'valuename' (lowercase).
# -> (value, operator, valuetype, absent_ok, note)
REG_SPECIAL = {
    'legalnoticetext': ('.+', 'match', 'String', False,
                        'Any non-empty logon banner text satisfies the check.'),
    'legalnoticecaption': ('.+', 'match', 'String', False,
                           'Any non-empty logon banner title satisfies the check.'),
    'scremoveoption': ('1,2,3', 'oneof', 'String', False,
                       '1 = Lock Workstation, 2 = Force Logoff, 3 = Disconnect if a Remote Desktop Services session.'),
    'nullsessionpipes': ('', 'eq', 'MultiString', True,
                         'The value must be empty (or absent) - no named pipe may be accessed anonymously. CIS also '
                         'allows BROWSER when the legacy Computer Browser service is enabled; that service only exists '
                         'when the SMB 1.0 feature is installed, so review it manually in that case.'),
    'nullsessionshares': ('', 'eq', 'MultiString', True,
                          'The value must be empty (or absent) - no share may be accessed anonymously.'),
    'allowedexactpaths\\machine': (','.join(ALLOWED_EXACT_PATHS), 'contains', 'MultiString', False,
                                   'All three default paths must be present and no others should be added.'),
    'allowedpaths\\machine': (','.join(ALLOWED_PATHS), 'contains', 'MultiString', False,
                              'All eleven default sub-paths must be present. The benchmark Audit text additionally lists '
                              'System\\CurrentControlSet\\Services\\CertSvc and System\\CurrentControlSet\\Services\\WINS, '
                              'which belong there only when the AD CS or WINS role is installed - they are allowed, not required.'),
    'logfilepath': ('.+', 'match', 'String', False, None),      # note built per firewall profile
    'disablebkgndgrouppolicy': ('', 'notexist', 'DWord', True,
                                'The policy must be Disabled, which means the value must NOT be present.'),
}

# Domain controllers differ where the benchmark has separate (DC only) items.
REG_SPECIAL_DC = {
    # 'LSARPC, NETLOGON, SAMR' and (legacy Computer Browser) 'BROWSER'. The engine
    # joins a REG_MULTI_SZ with '; ', so this accepts any subset of those four
    # pipes - the security point is that no OTHER pipe is anonymously reachable.
    'nullsessionpipes': (r'^((LSARPC|NETLOGON|SAMR|BROWSER)(;\s*|$))*$', 'match', 'MultiString', False,
                         'Only LSARPC, NETLOGON and SAMR may be listed (plus BROWSER when the legacy Computer Browser '
                         'service is enabled); any other named pipe is a Mismatch. Fewer pipes than that also passes.'),
}


# ------------------------------------------------------------------ helpers --
def split_title(title):
    """"Ensure 'X' is set to 'Y' (MS only)" -> ('X', "'Y'")"""
    t = ONLY_RE.sub('', title)
    m = re.match(r"^(?:Ensure|Configure)\s+'(.+?)'(?:\s+(?:is set to include|is set to|to include)\s+(.*)|\s+is configured.*)?$", t)
    if not m:
        return '', ''
    return m.group(1), (m.group(2) or '').strip()


def title_value(expected):
    """Account-policy phrase from the title -> (value, operator)."""
    t = expected.strip().strip("'").lower().replace(',', '')
    if t.startswith('enabled'):
        return '1', 'eq'
    if t.startswith('disabled'):
        return '0', 'eq'
    m = re.match(r'(\d+) or (?:fewer|less)\b.*but not 0', t)
    if m:
        return '1,' + m.group(1), 'between'
    m = re.match(r'(\d+) or (?:more|greater)\b', t)
    if m:
        return m.group(1), 'ge'
    m = re.match(r'(\d+) or (?:fewer|less)\b', t)
    if m:
        return m.group(1), 'le'
    return None, None


def title_direction(expected, val):
    """The Audit text often prints the bare threshold ("32768") where the title
    says "32,768 or greater" - return the operator the title implies."""
    flat = expected.replace(',', '')
    m = re.search(r'(\d+)\s*(?:%|KB|MB|days?|hours?|minutes?|seconds?|characters?)?\s+or\s+'
                  r'(more|greater|higher|fewer|less|lower)\b(.*)', flat, re.I)
    if not m or m.group(1) != val:
        return None, None
    if m.group(2).lower() in ('more', 'greater', 'higher'):
        return val, 'ge'
    if re.search(r'but not (?:0|never)', m.group(3), re.I):
        return '1,' + val, 'between'
    return val, 'le'


def special_for(path, name, profile):
    parent = path.rstrip('\\').split('\\')[-1].lower()
    tables = ([REG_SPECIAL_DC] if profile == 'DC' else []) + [REG_SPECIAL]
    for table in tables:
        hit = table.get('%s\\%s' % (parent, name.lower())) or table.get(name.lower())
        if hit:
            return hit
    return None


def conditional_principals(description):
    """Principals the recommended-state sentence allows only under a condition:
    "...: Administrators, ... SERVICE and (when the Web Server (IIS) Role with
    Web Services Role Service is installed) IIS_IUSRS." -> [('IIS_IUSRS', 'the
    Web Server (IIS) Role ... is installed')]. The condition can itself contain
    parentheses, so it is matched by depth rather than by a regex."""
    m = re.search(r'recommended state for this setting[^:]*:\s*(.*?)(?:\.\s+(?=[A-Z])|\.$|$)', description)
    if not m:
        return []
    stmt, out = m.group(1), []
    for start in (x.start() for x in re.finditer(r'\((?:when|if) ', stmt)):
        depth, j = 0, start
        while j < len(stmt):
            depth += {'(': 1, ')': -1}.get(stmt[j], 0)
            if depth == 0:
                break
            j += 1
        cond = stmt[start + 1:j].split(' ', 1)[1].strip()
        tail = re.split(r'\s+and\s+\(', stmt[j + 1:], maxsplit=1)[0]
        for n in re.split(r',\s*|\s+and\s+', tail):
            n = n.strip().strip("'").strip()
            if n:
                out.append((n, cond))
    return out


def squash(s):
    return re.sub(r'\s+', '', s).lower()


def build_notes(rec, short):
    parts = ['CIS %s (%s).' % (rec['section'], short)]
    for label, key in (('Description', 'description'), ('Rationale', 'rationale'), ('Impact', 'impact'),
                       ('Default value', 'default')):
        if rec[key]:
            parts.append('%s: %s' % (label, rec[key]))
    return ' '.join(parts)


def benchmark_name(txt, pdf_path):
    first = re.sub(r'\s+', ' ', txt[:txt.find('===PAGE 2===')])
    m = re.search(r'(CIS Microsoft Windows Server \d{4}\S* Benchmark)\s+(v\d+(?:\.\d+)*)', first)
    if m:
        return '%s %s' % (m.group(1), m.group(2))
    return os.path.splitext(os.path.basename(pdf_path))[0].replace('_', ' ')


def load_win11():
    """Cross-check sources from the Windows 11 CIS set."""
    try:
        w = json.load(open(P.POLICIES_CIS))
    except (OSError, ValueError):
        return {}, {}
    audit, rights = {}, {}
    for p in w:
        m = re.search(r"Ensure '(.+?)'", p['PolicyName'])
        if not m:
            continue
        if p.get('CheckType') == 'AuditPol':
            audit[m.group(1).lower()] = p['SettingName'].lower()
        elif p.get('CheckType') == 'SecEditPrivilege':
            rights[m.group(1).lower()] = p['SettingName']
    return audit, rights


# -------------------------------------------------------------------- build --
def privilege_check(base, rec, name, title, w11_rights, warnings, info):
    """User right -> SecEditPrivilege record (or None)."""
    sec, key = rec['section'], name.lower()
    const = USER_RIGHTS[key]
    if key in w11_rights and w11_rights[key] != const:
        warnings.append('%s: privilege constant %s differs from Policies-CIS.json (%s)'
                        % (sec, const, w11_rights[key]))
    val, sids, unmapped = principals_from_title(title)
    if not val:
        warnings.append('%s: cannot read the principals from "%s"' % (sec, title))
        return None
    sids = [s for s in sids.split(',') if s]
    notes = []
    if key.startswith('deny '):
        op = 'contains'          # the listed principals must all be denied
    elif not sids:
        op = 'setequals'         # "No One"
    else:
        op = 'subsetof'          # nobody outside the allow list
    if unmapped:
        op = 'contains'
        notes.append('CIS also permits %s, which has no well-known SID. This check therefore only verifies '
                     'that the mapped principals hold the right - review any additional holder manually.'
                     % ', '.join(unmapped))
        warnings.append('%s: no SID for %s' % (sec, ', '.join(unmapped)))
    # Principals the description allows only under a condition ("(when the
    # Web Server (IIS) Role ... is installed) IIS_IUSRS") belong in an allow
    # list - leaving them out makes every server with that role a Mismatch.
    if op == 'subsetof':
        for pname, cond in conditional_principals(rec['description']):
            sid = PRINCIPAL_SID.get(pname.lower())
            if sid and sid in sids:
                continue
            if sid:
                sids.append(sid)
                notes.append('%s (%s) is additionally allowed when %s.' % (pname, sid, cond))
            else:
                notes.append('CIS also allows %s when %s. It has no well-known SID, so on a system where that '
                             'applies this check reports a Mismatch - confirm the extra holder manually.' % (pname, cond))
                info.append('%s: conditional principal %s has no well-known SID (when %s)' % (sec, pname, cond))
    # A restricted service SID (S-1-5-99-<hash>) is exported by some builds in
    # its S-1-5-80 service-SID form; accept both, as Policies-CIS.json does.
    for s in list(sids):
        if s.startswith('S-1-5-99-'):
            twin = 'S-1-5-80-' + s[len('S-1-5-99-'):]
            if twin not in sids:
                sids.append(twin)
                notes.append('RESTRICTED SERVICES\\PrintSpoolerService is matched by its name-derived service SID '
                             '(%s, and the equivalent %s form).' % (s, twin))
    base.update(CheckType='SecEditPrivilege', RegistryPath='secedit /export -> [Privilege Rights]',
                SettingName=const, RecommendedValue=val, RecommendedSids=','.join(sids), Operator=op, ValueType='')
    if notes:
        base['Notes'] += ' ' + ' '.join(notes)
    return base


def fold_privileges(records, warnings, info):
    """Some benchmarks give one right two recommendations in the same profile
    (Server 2019 v5.0.0: 'Impersonate a client after authentication' with and
    without RESTRICTED SERVICES\\PrintSpoolerService). Two allow-list checks on
    one right can only disagree in one direction - a machine that meets the
    narrower list always meets the wider one - so they are reported once, as the
    wider list, instead of as a check that some compliant machines always fail."""
    by_right = {}
    for r in records:
        if r['CheckType'] == 'SecEditPrivilege':
            by_right.setdefault(r['SettingName'], []).append(r)
    drop = set()
    for const, group in by_right.items():
        if len(group) < 2:
            continue
        sets = [set(filter(None, r['RecommendedSids'].split(','))) for r in group]
        widest = max(range(len(group)), key=lambda i: len(sets[i]))
        if not all(r['Operator'] == 'subsetof' for r in group) or not all(s <= sets[widest] for s in sets):
            warnings.append('%s: %s recommendations that cannot be folded (%s)'
                            % (const, len(group), ', '.join(r['CisSection'] for r in group)))
            continue
        keep = group[widest]
        for i, r in enumerate(group):
            if i == widest:
                continue
            extra = sorted(sets[widest] - sets[i])
            keep['Notes'] += (' CIS %s gives this right a narrower list (%s). Any machine that meets it also meets '
                              'this one, so it is folded into this check rather than reported twice.'
                              % (r['CisSection'], r['RecommendedValue']))
            drop.add(id(r))
            info.append('%s folded into %s (%s; the wider list adds %s)'
                        % (r['CisSection'], keep['CisSection'], const, ', '.join(extra) or 'nothing'))
    return [r for r in records if id(r) not in drop]


def build_profile(profile, pdf_path, slug, bench, groups, recs, w11_audit, w11_rights, out_path=None):
    applic, short = PROFILES[profile]
    selected = [r for r in recs if applic in r['profiles']]
    records, warnings, info = [], [], []

    for rec in selected:
        sec, title = rec['section'], rec['title']
        name, expected = split_title(title)
        category = category_for(sec, groups)
        base = {
            'Category': category,
            'PolicyName': '%s %s' % (sec, title),
            'Scope': 'User' if sec.startswith('19.') else 'Computer',
            'CheckType': 'Registry',
            'PolicyPath': rec['gp_path'],
            'RegistryPath': '',
            'SettingName': '',
            'ValueType': '',
            'RecommendedValue': '',
            'Operator': 'eq',
            'Priority': priority_for('L1', sec, title, category),
            'CisSection': sec,
            'CisLevel': 'L1',
            'CisBenchmark': '%s - %s' % (bench, applic),
            'Notes': build_notes(rec, short),
        }
        key = name.lower()

        # ---- advanced audit policy (auditpol) ------------------------------
        if rec['audit_guid'] or sec.startswith('17.'):
            guid = rec['audit_guid']
            if not guid:
                warnings.append('%s: no auditpol subcategory GUID in the Audit section' % sec)
                continue
            if key in w11_audit and w11_audit[key] != guid:
                warnings.append('%s: GUID %s differs from Policies-CIS.json (%s) for "%s"'
                                % (sec, guid, w11_audit[key], name))
            exp = expected.strip("'")
            if 'Success and Failure' in exp:
                flags = 3
            elif exp == 'Success':
                flags = 1
            elif exp == 'Failure':
                flags = 2
            else:
                warnings.append('%s: cannot infer audit flags from "%s"' % (sec, title))
                continue
            base.update(CheckType='AuditPol', RegistryPath='auditpol /backup -> {%s}' % guid.upper(),
                        SettingName=guid, RecommendedValue='Success and Failure' if flags == 3 else exp,
                        RequiredFlags=flags, Operator='', ValueType='')
            records.append(base)
            continue

        # ---- registry -------------------------------------------------------
        if rec['regs']:
            regs = [r for r in rec['regs'] if r['name']]
            if not regs:
                warnings.append('%s: registry location without a value name' % sec)
                continue
            vtype = TYPE_MAP.get(rec['reg_type'], 'DWord')
            expect = rec['reg_expect']

            # "1 (EnableSmartScreen) and REG_SZ value of Block (ShellSmartScreenLevel)"
            pairs = {}
            for m in re.finditer(r'(?:(REG_\w+)\s+value of\s+)?(\S+)\s+\((\w+)\)', expect):
                pairs[m.group(3).lower()] = (m.group(2), TYPE_MAP.get(m.group(1) or rec['reg_type'], vtype))

            rows = []
            for r in regs:
                note = ''
                absent_ok = False
                special = special_for(r['path'], r['name'], profile)
                if special:
                    val, op, vt, absent_ok, note = special
                    if note is None:      # firewall log path: per-profile suggestion
                        prof = re.search(r'\\(Domain|Private|Public)Profile', r['path'])
                        note = ('Any configured log file path satisfies the check; CIS suggests '
                                '%%SystemRoot%%\\System32\\logfiles\\firewall\\%sfw.log.'
                                % (prof.group(1).lower() if prof else '<profile>'))
                    if op == 'contains':
                        body = squash(rec['description'] + rec['audit'])
                        for tok in val.split(','):
                            if squash(tok) not in body:
                                warnings.append('%s: "%s" from the curated list is not in the benchmark text'
                                                % (sec, tok))
                elif r['name'].lower() in pairs:
                    val, vt = pairs[r['name'].lower()]
                    op = 'eq'
                else:
                    vt = vtype
                    val, op, absent_ok = parse_expect(expect, rec['reg_type'])
                    if val is None and expect:
                        tokens = [t.strip() for t in expect.split(',')]
                        if all(re.match(r'^\w+=\w+$', t) for t in tokens):
                            # Hardened UNC Paths: every flag must be present
                            val, op = ','.join(tokens), 'contains'
                        elif rec['reg_type'] in ('REG_SZ', 'REG_EXPAND_SZ') and ' ' not in expect:
                            val, op = expect, 'eq'          # e.g. an SDDL string
                    if val is None and not expect:
                        val, op = title_value(expected)
                        if val is not None:
                            vt = 'DWord'
                            info.append('%s %s: no value in the Audit text, %s %s taken from the title'
                                        % (sec, r['name'], op, val))
                    if op == 'eq' and val is not None and re.match(r'^\d+$', val):
                        v2, op2 = title_direction(expected, val)
                        if op2:
                            info.append('%s %s: Audit text says %s, title %s -> %s %s'
                                        % (sec, r['name'], val, expected, op2, v2))
                            val, op = v2, op2
                if val is None:
                    warnings.append('%s: no recommended value for %s (Audit text: %r)' % (sec, r['name'], expect))
                    continue
                rows.append((r, val, op, vt, absent_ok, note))

            names = [r['name'].lower() for r in regs]
            for r, val, op, vt, absent_ok, note in rows:
                rec_out = dict(base)
                if len(rows) > 1:
                    label = r['name'].split('\\')[-1] or r['name']
                    if names.count(r['name'].lower()) > 1 and '\\' not in r['name']:
                        label += ', 32-bit view' if 'wow6432node' in r['path'].lower() else ', 64-bit view'
                    rec_out['PolicyName'] = '%s %s (%s)' % (sec, title, label)
                rec_out.update(RegistryPath=r['path'], SettingName=r['name'], ValueType=vt,
                               RecommendedValue=val, Operator=op)
                if absent_ok:
                    rec_out['AbsentIsCompliant'] = True
                    if op != 'notexist':
                        rec_out['Notes'] += ' The value being absent is also compliant.'
                if note:
                    rec_out['Notes'] += ' ' + note
                records.append(rec_out)
            continue

        # ---- account policy (secedit [System Access]) ----------------------
        if key in SECEDIT:
            val, op = title_value(expected)
            if val is None:
                warnings.append('%s: cannot read a value from "%s"' % (sec, title))
                continue
            base.update(CheckType='SecEditAccess', RegistryPath='secedit /export -> [System Access]',
                        SettingName=SECEDIT[key], RecommendedValue=val, Operator=op, ValueType='')
            records.append(base)
            continue

        # ---- built-in accounts ---------------------------------------------
        if key in LOCALUSER:
            prop, val, op = LOCALUSER[key]
            base.update(CheckType='LocalUser', RegistryPath='Get-LocalUser (SID *-%s)' % prop.split(':')[0],
                        SettingName=prop, RecommendedValue=val, Operator=op, ValueType='')
            if profile == 'DC':
                base['Notes'] += (' On a domain controller there is no local account database: RID %s is the '
                                  'domain\'s built-in account, which is what this recommendation targets.'
                                  % prop.split(':')[0])
            records.append(base)
            continue

        # ---- user rights (secedit [Privilege Rights]) -----------------------
        if key in USER_RIGHTS:
            r = privilege_check(base, rec, name, title, w11_rights, warnings, info)
            if r:
                records.append(r)
            continue

        warnings.append('%s: no check could be derived (%s)' % (sec, title))

    records = fold_privileges(records, warnings, info)
    out_path = out_path or P.policies_server(slug, profile)
    json.dump(ordered(records), open(out_path, 'w'), indent=2, ensure_ascii=False)

    print('%s  [%s]' % (bench, applic))
    print('  wrote          :', os.path.relpath(out_path, P.REPO))
    print('  recommendations: %d in profile (of %d in the benchmark)' % (len(selected), len(recs)))
    kinds = {}
    for r in records:
        kinds[r['CheckType']] = kinds.get(r['CheckType'], 0) + 1
    print('  checks         : %d  (%s)' % (len(records), ', '.join('%s %d' % kv for kv in sorted(kinds.items()))))
    if info:
        print('  derived / folded (%d):' % len(info))
        for a in info:
            print('    ~', a)
    print('  warnings       :', len(warnings))
    for w in warnings:
        print('    !', w)
    return records, warnings


def build(pdf_path, profiles, out_path=None):
    slug = P.benchmark_slug(pdf_path)
    work = P.work_dir(slug)
    txt = extract_text(pdf_path, os.path.join(work, 'layout.txt'))
    groups, recs = parse_pdf(txt)
    json.dump({'groups': groups, 'recs': recs}, open(os.path.join(work, 'recs.json'), 'w'),
              indent=1, ensure_ascii=False)
    bench = benchmark_name(txt, pdf_path)
    w11_audit, w11_rights = load_win11()
    for profile in profiles:
        build_profile(profile, pdf_path, slug, bench, groups, recs, w11_audit, w11_rights, out_path)
        print()


def main():
    ap = P.parser(__doc__)
    ap.add_argument('--pdf', default=None, help='one CIS Windows Server benchmark PDF (default: all in sources/)')
    ap.add_argument('--profile', choices=sorted(PROFILES), action='append',
                    help='profile(s) to build (default: all)')
    ap.add_argument('--out', default=None, help='output path (only with --pdf and a single --profile)')
    args = ap.parse_args()
    profiles = args.profile or ['MS', 'DC']
    if args.out and (not args.pdf or len(profiles) != 1):
        raise SystemExit('--out needs --pdf and exactly one --profile')
    if args.pdf:
        pdfs = [args.pdf]
    else:
        pdfs = P.find_all('CIS_Microsoft_Windows_Server_*_Benchmark_*.pdf')
        if not pdfs:
            raise SystemExit('no CIS_Microsoft_Windows_Server_*_Benchmark_*.pdf in %s' % P.SOURCES)
        years = [P.benchmark_slug(p) for p in pdfs]
        dup = sorted(set(y for y in years if years.count(y) > 1))
        if dup:
            raise SystemExit('more than one PDF for %s - pass --pdf explicitly' % ', '.join(dup))
    for pdf in pdfs:
        build(pdf, profiles, args.out)


if __name__ == '__main__':
    main()
