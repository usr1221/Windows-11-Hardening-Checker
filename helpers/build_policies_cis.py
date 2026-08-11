#!/usr/bin/env python3
r"""Step 3 - build Policies-CIS.json.

Sources, in order of authority:
  * PDF Audit section   - registry location (HIVE\key:ValueName), REG_* type and
    the expected value phrase ("900 or less, but not 0"). See parse_cis_pdf.py.
  * report OVAL criteria - cross-check of the value name and expected values.
  * curated tables below - the checks that are not registry-backed: account
    policy and user rights (secedit), audit subcategories (auditpol) and the
    built-in local accounts.

User rights are derived from the CIS recommendation title itself and then
cross-checked against Policies.json; any disagreement is printed as a warning.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths as P

RULES = json.load(open(P.RULES_JSON))
PDF = json.load(open(P.PDF_JSON))
GROUPS = json.load(open(P.GROUPS_JSON))
LEGACY = json.load(open(P.POLICIES_ASD))

legacy_priv = {p['PolicyName'].lower(): p for p in LEGACY if p.get('CheckType') == 'SecEditPrivilege'}
legacy_audit = {p['PolicyName'].lower(): p for p in LEGACY if p.get('CheckType') == 'AuditPol'}

# ---------------------------------------------------------------- curated ---
# secedit [System Access] checks. Values are in the units secedit exports
# (days / minutes / count), NOT the seconds used by the OVAL content.
SECEDIT = {
    '1.1.1': ('PasswordHistorySize', '24', 'ge'),
    '1.1.2': ('MaximumPasswordAge', '1,365', 'between'),
    '1.1.3': ('MinimumPasswordAge', '1', 'ge'),
    '1.1.4': ('MinimumPasswordLength', '14', 'ge'),
    '1.1.5': ('PasswordComplexity', '1', 'eq'),
    '1.1.7': ('ClearTextPassword', '0', 'eq'),
    '1.2.1': ('LockoutDuration', '15', 'ge'),
    '1.2.2': ('LockoutBadCount', '1,5', 'between'),
    '1.2.3': ('AllowAdministratorLockout', '1', 'eq'),
    '1.2.4': ('ResetLockoutCount', '15', 'ge'),
    '2.3.10.1': ('LSAAnonymousNameLookup', '0', 'eq'),
    '2.3.11.5': ('ForceLogoffWhenHourExpire', '1', 'eq'),
}

# Local account checks (RID:Property), evaluated with Get-LocalUser.
LOCALUSER = {
    '2.3.1.1': ('501:Enabled', 'False', 'eq'),
    '2.3.1.3': ('500:Name', 'Administrator', 'ne'),
    '2.3.1.4': ('501:Name', 'Guest', 'ne'),
}

# Privilege constants for the user rights Policies.json does not carry.
PRIV_CONST = {
    '2.2.4':  'SeIncreaseQuotaPrivilege',
    '2.2.13': 'SeCreateSymbolicLinkPrivilege',
    '2.2.18': 'SeDenyInteractiveLogonRight',
    '2.2.22': 'SeAuditPrivilege',
    '2.2.24': 'SeIncreaseBasePriorityPrivilege',
    '2.2.30': 'SeRelabelPrivilege',
    '2.2.34': 'SeSystemProfilePrivilege',
    '2.2.35': 'SeAssignPrimaryTokenPrivilege',
    '2.2.37': 'SeShutdownPrivilege',
}

# Well-known principals as CIS spells them in the recommendation titles.
PRINCIPAL_SID = {
    'administrators': 'S-1-5-32-544',
    'users': 'S-1-5-32-545',
    'guests': 'S-1-5-32-546',
    'remote desktop users': 'S-1-5-32-555',
    'local service': 'S-1-5-19',
    'network service': 'S-1-5-20',
    'service': 'S-1-5-6',
    'local account': 'S-1-5-113',
    'local account and member of administrators group': 'S-1-5-114',
    'window manager\\window manager group': 'S-1-5-90-0',
    'nt service\\wdiservicehost': 'S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420',
    'nt virtual machine\\virtual machines': 'S-1-5-83-0',
}

# Principals CIS allows conditionally, added on top of the title-derived set.
PRIV_SIDS_EXTRA = {
    '2.2.13': (['S-1-5-83-0'],
               'NT VIRTUAL MACHINE\\Virtual Machines (S-1-5-83-0) is additionally allowed when Hyper-V is installed.'),
}

def principals_from_title(title):
    """('Administrators, LOCAL SERVICE') -> friendly text, SID csv, unmapped[]"""
    m = re.search(r"(?:is set to|to include)\s+'(.+)'\s*$", title)
    if not m:
        return '', '', []
    text = m.group(1).strip()
    if text.lower() in ('no one', 'no-one', 'none'):
        return 'No One', '', []
    names = [n.strip() for n in text.split(',') if n.strip()]
    sids, unmapped = [], []
    for n in names:
        sid = PRINCIPAL_SID.get(n.lower())
        if sid:
            if sid not in sids:
                sids.append(sid)
        else:
            unmapped.append(n)
    return text, ','.join(sids), unmapped

# Audit subcategory GUIDs that Policies.json does not already carry.
AUDIT_EXTRA = {
    '17.2.1': ('0cce9239-69ae-11d9-bed3-505054503030', 'Audit Application Group Management'),
    '17.7.3': ('0cce9231-69ae-11d9-bed3-505054503030', 'Audit Authorization Policy Change'),
    '17.9.1': ('0cce9213-69ae-11d9-bed3-505054503030', 'Audit IPsec Driver'),
}

# Registry checks whose expected value cannot be read straight off the PDF.
# section: (value, operator, valuetype, absent_ok, note)
REG_SPECIAL = {
    '2.3.7.4':  ('.+', 'match', 'String', False, 'Any non-empty logon banner text satisfies the check.'),
    '2.3.7.5':  ('.+', 'match', 'String', False, 'Any non-empty logon banner title satisfies the check.'),
    '2.3.7.7':  ('5,14', 'between', 'DWord', False, ''),
    '2.3.7.8':  ('1,2,3', 'oneof', 'String', False, '1 = Lock Workstation, 2 = Force Logoff, 3 = Disconnect.'),
    '2.3.10.6': ('', 'eq', 'MultiString', True, 'The value must be empty (or absent) - no named pipe may be accessed anonymously.'),
    '2.3.10.7': ('System\\CurrentControlSet\\Control\\ProductOptions,System\\CurrentControlSet\\Control\\Server Applications,Software\\Microsoft\\Windows NT\\CurrentVersion',
                 'contains', 'MultiString', False, 'All three default paths must be present and no others should be added.'),
    '2.3.10.8': ('System\\CurrentControlSet\\Control\\Print\\Printers,System\\CurrentControlSet\\Services\\Eventlog,Software\\Microsoft\\OLAP Server,Software\\Microsoft\\Windows NT\\CurrentVersion\\Print,Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows,System\\CurrentControlSet\\Control\\ContentIndex,System\\CurrentControlSet\\Control\\Terminal Server,System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig,System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration,Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib,System\\CurrentControlSet\\Services\\SysmonLog',
                 'contains', 'MultiString', False, 'All eleven default sub-paths must be present.'),
    '2.3.10.11': ('', 'eq', 'MultiString', True, 'The value must be empty (or absent) - no share may be accessed anonymously.'),
    '9.1.4':    ('.+', 'match', 'String', False, 'Any configured log file path satisfies the check; CIS suggests %SystemRoot%\\System32\\logfiles\\firewall\\domainfw.log.'),
    '9.2.4':    ('.+', 'match', 'String', False, 'Any configured log file path satisfies the check; CIS suggests %SystemRoot%\\System32\\logfiles\\firewall\\privatefw.log.'),
    '9.3.6':    ('.+', 'match', 'String', False, 'Any configured log file path satisfies the check; CIS suggests %SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log.'),
    '18.5.1':   ('0', 'eq', 'String', False, ''),
    '18.9.19.5': ('', 'notexist', 'DWord', True, 'The policy must be Disabled, which means the value must NOT be present.'),
    '18.10.42.6.1.1': ('1', 'eq', 'DWord', False, ''),
    # "16,384 KB or greater" - the PDF prints the bare number.
    '9.1.5':    ('16384', 'ge', 'DWord', False, ''),
    '9.2.5':    ('16384', 'ge', 'DWord', False, ''),
    '9.3.7':    ('16384', 'ge', 'DWord', False, ''),
}

# Rules that expand into several concrete checks.
ASR_RULES = {
    '26190899-1602-49e8-8b27-eb1d0a1ce869': 'Block Office communication application from creating child processes',
    '3b576869-a4ec-4529-8536-b80a7769e899': 'Block Office applications from creating executable content',
    '56a863a9-875e-4185-98a7-b882c64b5ce5': 'Block abuse of exploited vulnerable signed drivers',
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc': 'Block execution of potentially obfuscated scripts',
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84': 'Block Office applications from injecting code into other processes',
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c': 'Block Adobe Reader from creating child processes',
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b': 'Block Win32 API calls from Office macros',
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2': 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)',
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4': 'Block untrusted and unsigned processes that run from USB',
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550': 'Block executable content from email client and webmail',
    'd3e037e1-3eb8-44c8-a917-57927947596d': 'Block JavaScript or VBScript from launching downloaded executable content',
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a': 'Block all Office applications from creating child processes',
    'e6db77e5-3df2-4cf1-b95a-636979351e5b': 'Block persistence through WMI event subscription',
}

TYPE_MAP = {'REG_DWORD': 'DWord', 'REG_SZ': 'String', 'REG_MULTI_SZ': 'MultiString',
            'REG_EXPAND_SZ': 'ExpandString', 'REG_QWORD': 'QWord', 'REG_BINARY': 'Binary'}

# ------------------------------------------------------------------ helpers --
def category_for(section):
    """Nearest enclosing benchmark group title, e.g. 18.10.42.13 -> 'Scan'."""
    parts = section.split('.')
    for i in range(len(parts) - 1, 0, -1):
        pref = '.'.join(parts[:i])
        if pref in GROUPS:
            name = GROUPS[pref]
            if i == 1:
                return name
            # qualify short/ambiguous leaf names with their parent
            parent = None
            for j in range(i - 1, 0, -1):
                p2 = '.'.join(parts[:j])
                if p2 in GROUPS:
                    parent = GROUPS[p2]
                    break
            if parent and len(name) < 24 and parent != name:
                return '%s - %s' % (parent, name)
            return name
    return GROUPS.get(parts[0], 'CIS Benchmark')

def profile_level(section):
    body = PDF.get(section, {}).get('body', '')
    m = re.search(r'Profile Applicability\s*:\s*(.*?)Description', body)
    txt = m.group(1) if m else ''
    lv = []
    if 'Level 1' in txt: lv.append('L1')
    if 'Level 2' in txt: lv.append('L2')
    if 'BitLocker' in txt: lv.append('BL')
    if 'Next Generation' in txt or '(NG)' in txt: lv.append('NG')
    return '+'.join(lv) or 'L1'

# Every rule in this report is Level 1, so the CIS profile alone cannot rank
# them. Priority is therefore derived from what the setting protects.
HIGH_PAT = re.compile(r'''(?ix)
    ntlm|lsa|lsass|credential|password|kerberos|smb|lanman|anonymous|null\ session|
    uac|user\ account\ control|elevat|administrator|admin\ approval|privilege|
    firewall|remote\ desktop|rdp|winrm|remote\ assistance|rpc|spooler|print\ driver|
    defender|attack\ surface|asr\ rule|network\ protection|smartscreen|real-time|
    exploit|virtualization\ based|credential\ guard|secure\ boot|driver|
    autorun|autoplay|macro|script|installer|always\ install|token|delegation|
    audit|logon|log\ on|wdigest|laps|sam|guest|blank\ password|encryption|signing|
    sign\ communications|insecure\ guest|mailslot|source\ routing|wpad|recall''')
LOW_PAT = re.compile(r'''(?ix)
    lock\ screen\ camera|slide\ show|slideshow|spotlight|toast|consumer|cortana|
    xbox|game\ recording|gamedvr|game\ save|ink\ workspace|rss|news|feeds|
    sharing\ files\ within\ their\ profile|windows\ media\ player|
    offer\ to\ update|delivery\ optimization|device\ metadata|
    online\ speech|search\ and\ cortana|third-party\ content|app\ notifications''')

def priority_for(level, section, title, category):
    text = '%s %s' % (title, category)
    if LOW_PAT.search(text):
        return 'Low'
    if HIGH_PAT.search(text):
        return 'High'
    return 'Medium'

def section_of(body, name, nxt):
    m = re.search(re.escape(name) + r'\s*:\s*(.*?)(?=' + nxt + r')', body, re.S)
    return re.sub(r'\s+', ' ', m.group(1)).strip() if m else ''

def build_notes(rule, level):
    body = PDF.get(rule['section'], {}).get('body', '')
    default = section_of(body, 'Default Value', r'References\s*:|CIS Controls\s*:|$')
    parts = ['CIS %s (%s).' % (rule['section'], level)]
    if rule['description']:
        parts.append('Description: ' + re.sub(r'\s+', ' ', rule['description']).strip())
    if rule['rationale']:
        parts.append('Rationale: ' + re.sub(r'\s+', ' ', rule['rationale']).strip())
    imp = re.search(r'Impact:\s*(.*)$', re.sub(r'\s+', ' ', rule['remediation']), re.S)
    if imp:
        parts.append('Impact: ' + imp.group(1).strip())
    if default:
        parts.append('Default value: ' + default)
    return ' '.join(parts)

def parse_expect(expect, regtype):
    """Turn the PDF's 'expected value' phrase into (value, operator, absent_ok)."""
    e = re.sub(r'\s+', ' ', expect or '').strip().rstrip('.')
    absent_ok = False
    m = re.match(r'^(\d+) or that the key does not exist$', e, re.I)
    if m:
        return m.group(1), 'eq', True
    m = re.match(r'^(\d+) or less, but not 0$', e, re.I)
    if m:
        return '1,' + m.group(1), 'between', False
    m = re.match(r'^(\d+) or less$', e, re.I)
    if m:
        return m.group(1), 'le', False
    m = re.match(r'^(\d+) or (?:more|greater)$', e, re.I)
    if m:
        return m.group(1), 'ge', False
    m = re.match(r'^anything other than (\d+)$', e, re.I)
    if m:
        return m.group(1), 'ne', False
    m = re.match(r'^(\d+)$', e)
    if m:
        return m.group(1), 'eq', False
    nums = re.findall(r'\d+', e)
    if nums and re.match(r'^[\d,\sor]+$', e, re.I):
        return ','.join(nums), 'oneof', False
    return None, None, absent_ok

def oval_values(rule):
    out = []
    for c in rule['criteria']:
        m = re.match(r"Ensure '(.+?)' is 'Windows: Registry Value'(?: not set)? to '(.*)'$", c)
        if m:
            out.append(m.group(2))
    return out

# -------------------------------------------------------------------- build --
records = []
warnings = []

for rule in RULES:
    sec = rule['section']
    pdf = PDF.get(sec, {})
    level = profile_level(sec)
    base = {
        'Category': category_for(sec),
        'PolicyName': '%s %s' % (sec, rule['title']),
        'Scope': 'User' if sec.startswith('19.') else 'Computer',
        'CheckType': 'Registry',
        'PolicyPath': rule['gp_paths'][0] if rule['gp_paths'] else '',
        'RegistryPath': '',
        'SettingName': '',
        'ValueType': '',
        'RecommendedValue': '',
        'Operator': 'eq',
        'Priority': priority_for(level, sec, rule['title'], category_for(sec)),
        'CisSection': sec,
        'CisLevel': level,
        'Notes': build_notes(rule, level),
    }

    # ---- non-registry check types -----------------------------------------
    if sec in SECEDIT:
        name, val, op = SECEDIT[sec]
        base.update(CheckType='SecEditAccess', RegistryPath='secedit /export -> [System Access]',
                    SettingName=name, RecommendedValue=val, Operator=op, ValueType='')
        records.append(base); continue

    if sec in LOCALUSER:
        name, val, op = LOCALUSER[sec]
        base.update(CheckType='LocalUser', RegistryPath='Get-LocalUser (SID *-%s)' % name.split(':')[0],
                    SettingName=name, RecommendedValue=val, Operator=op, ValueType='')
        records.append(base); continue

    if sec.startswith('2.2.'):
        title = re.match(r"Ensure '(.+?)'", rule['title'])
        key = title.group(1).lower() if title else ''
        const = PRIV_CONST.get(sec)
        if not const and key in legacy_priv:
            const = legacy_priv[key]['SettingName']
        if not const:
            warnings.append('%s: no privilege constant' % sec); continue

        # The principal list is taken from the CIS title itself, so the SID set
        # can never drift from the recommendation it claims to check.
        val, sids, unmapped = principals_from_title(rule['title'])
        extra_note = ''
        if key.startswith('deny '):
            op = 'contains'          # required principals must all be denied
        elif not sids:
            op = 'setequals'         # "No One" - the right must be held by nobody
        else:
            op = 'subsetof'          # no principal outside the allow list
        if unmapped:
            # e.g. RESTRICTED SERVICES\PrintSpoolerService, which has no stable
            # well-known SID: verify the listed principals are present instead of
            # rejecting everything else, and say so.
            op = 'contains'
            extra_note = ('CIS also permits %s, which has no well-known SID. This check therefore only verifies '
                          'that the mapped principals hold the right - review any additional holder manually.'
                          % ', '.join(unmapped))
        if sec in PRIV_SIDS_EXTRA:
            sids = ','.join([s for s in sids.split(',') if s] + PRIV_SIDS_EXTRA[sec][0])
            extra_note = (extra_note + ' ' + PRIV_SIDS_EXTRA[sec][1]).strip()

        # Cross-check against the hand-written table that shipped with
        # Policies.json and report any disagreement.
        if key in legacy_priv:
            old = set(filter(None, legacy_priv[key]['RecommendedSids'].split(',')))
            new = set(filter(None, sids.split(',')))
            if old != new:
                warnings.append('%s: SID set differs from Policies.json (was %s, now %s)'
                                % (sec, sorted(old) or ['<none>'], sorted(new) or ['<none>']))
        base.update(CheckType='SecEditPrivilege', RegistryPath='secedit /export -> [Privilege Rights]',
                    SettingName=const, RecommendedValue=val, RecommendedSids=sids, Operator=op, ValueType='')
        if extra_note:
            base['Notes'] += ' ' + extra_note
        records.append(base); continue

    if sec.startswith('17.'):
        title = re.match(r"Ensure '(.+?)'", rule['title'])
        key = title.group(1).lower() if title else ''
        if sec in AUDIT_EXTRA:
            guid, disp = AUDIT_EXTRA[sec]
        elif key in legacy_audit:
            guid, disp = legacy_audit[key]['SettingName'], legacy_audit[key]['PolicyName']
        else:
            warnings.append('%s: no auditpol GUID' % sec); continue
        t = rule['title']
        if 'Success and Failure' in t:
            flags, val = 3, 'Success and Failure'
        elif "include 'Success'" in t or t.rstrip().endswith("'Success'"):
            flags, val = 1, 'Success'
        elif "include 'Failure'" in t or t.rstrip().endswith("'Failure'"):
            flags, val = 2, 'Failure'
        else:
            warnings.append('%s: cannot infer audit flags from "%s"' % (sec, t)); continue
        base.update(CheckType='AuditPol', RegistryPath='auditpol /backup -> {%s}' % guid.upper(),
                    SettingName=guid, RecommendedValue=val, RequiredFlags=flags, Operator='', ValueType='')
        records.append(base); continue

    # ---- registry checks ---------------------------------------------------
    regs = pdf.get('regs') or []
    regs = [r for r in regs if r['name']] or regs
    if not regs:
        warnings.append('%s: no registry mapping' % sec); continue

    for r in regs:
        # PDF line-wrapping leaves "{827D319E -6EAC-...}" / "f15576e8 -98b7-..."
        r['path'] = re.sub(r'\s+-', '-', r['path'])
        r['path'] = r['path'].replace('\\windows Defender', '\\Windows Defender')
        r['path'] = re.sub(r'^HKU\\\[USER SID\]\\', r'HKCU\\', r['path'])
    regtype = pdf.get('reg_type', '')
    vtype = TYPE_MAP.get(regtype, 'DWord')
    val, op, absent_ok = parse_expect(pdf.get('reg_expect', ''), regtype)
    if val is None:
        ov = oval_values(rule)
        if len(ov) == 1:
            val, op = ov[0], 'eq'
        elif len(ov) > 1:
            val, op = ','.join(dict.fromkeys(ov)), 'oneof'

    note_extra = ''
    if sec in REG_SPECIAL:
        val, op, vtype, absent_ok, note_extra = REG_SPECIAL[sec]

    # ---- multi-value expansions -------------------------------------------
    if sec == '18.10.42.6.1.2':
        path = regs[0]['path']
        for guid, name in ASR_RULES.items():
            rec = dict(base)
            rec.update(PolicyName='%s ASR rule: %s' % (sec, name), RegistryPath=path,
                       SettingName=guid, ValueType='String', RecommendedValue='1', Operator='eq',
                       Notes=base['Notes'] + ' ASR rule %s (%s); 1 = Block.' % (guid, name))
            records.append(rec)
        continue

    if sec == '18.6.14.1':
        for share in ('\\\\*\\NETLOGON', '\\\\*\\SYSVOL'):
            rec = dict(base)
            rec.update(PolicyName='%s %s (%s)' % (sec, rule['title'], share.split('\\')[-1]),
                       RegistryPath=regs[0]['path'], SettingName=share, ValueType='String',
                       RecommendedValue='RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1',
                       Operator='contains')
            records.append(rec)
        continue

    if sec in ('18.10.77.2.1', '18.10.94.4.2', '18.4.4'):
        pairs = {
            '18.10.77.2.1': [(regs[0]['path'], 'EnableSmartScreen', 'DWord', '1', 'eq'),
                             (regs[0]['path'], 'ShellSmartScreenLevel', 'String', 'Block', 'eq')],
            '18.10.94.4.2': [(regs[0]['path'], 'DeferQualityUpdates', 'DWord', '1', 'eq'),
                             (regs[0]['path'], 'DeferQualityUpdatesPeriodInDays', 'DWord', '0', 'eq')],
            '18.4.4': [(r['path'], 'EnableCertPaddingCheck', 'String', '1', 'eq') for r in regs],
        }[sec]
        for path, name, vt, v, o in pairs:
            rec = dict(base)
            rec.update(PolicyName='%s %s (%s)' % (sec, rule['title'], name), RegistryPath=path,
                       SettingName=name, ValueType=vt, RecommendedValue=v, Operator=o)
            records.append(rec)
        continue

    reg = regs[0]
    if val is None:
        warnings.append('%s: no recommended value' % sec); continue
    base.update(RegistryPath=reg['path'], SettingName=reg['name'], ValueType=vtype,
                RecommendedValue=val, Operator=op)
    if absent_ok:
        base['AbsentIsCompliant'] = True
        base['Notes'] += ' The value being absent is also compliant.'
    if note_extra:
        base['Notes'] += ' ' + note_extra
    records.append(base)

# ---- field ordering ---------------------------------------------------------
ORDER = ['Category', 'PolicyName', 'Scope', 'CheckType', 'PolicyPath', 'RegistryPath', 'SettingName',
         'ValueType', 'RecommendedValue', 'RecommendedSids', 'RequiredFlags', 'Operator',
         'AbsentIsCompliant', 'Priority', 'CisSection', 'CisLevel', 'Notes']
ordered = []
for r in records:
    ordered.append({k: r[k] for k in ORDER if k in r})

json.dump(ordered, open(P.POLICIES_CIS, 'w'), indent=2, ensure_ascii=False)
print('wrote', os.path.relpath(P.POLICIES_CIS, P.REPO))
print('records:', len(ordered))
print('warnings:', len(warnings))
for w in warnings:
    print('  !', w)
