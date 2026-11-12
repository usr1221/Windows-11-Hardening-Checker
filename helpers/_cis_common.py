"""Tables and helpers shared by the CIS policy-set generators.

build_policies_cis.py (Windows 11, report + PDF) and
build_policies_cis_server.py (Windows Server, PDF only) both import from here,
so a principal SID, a priority rule or an expected-value phrase is defined once.
"""
import re

# Well-known principals as CIS spells them in the recommendation titles.
PRINCIPAL_SID = {
    'administrators': 'S-1-5-32-544',
    'users': 'S-1-5-32-545',
    'guests': 'S-1-5-32-546',
    'backup operators': 'S-1-5-32-551',
    'remote desktop users': 'S-1-5-32-555',
    'iis_iusrs': 'S-1-5-32-568',
    'everyone': 'S-1-1-0',
    'service': 'S-1-5-6',
    'enterprise domain controllers': 'S-1-5-9',
    'authenticated users': 'S-1-5-11',
    'local service': 'S-1-5-19',
    'network service': 'S-1-5-20',
    'local account': 'S-1-5-113',
    'local account and member of administrators group': 'S-1-5-114',
    'window manager\\window manager group': 'S-1-5-90-0',
    'nt service\\wdiservicehost': 'S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420',
    'nt virtual machine\\virtual machines': 'S-1-5-83-0',
    # Restricted service identity of the split print spooler (24H2+). The
    # sub-authorities are the SHA-1 hash of the uppercased service name, so the
    # SID is the same on every machine; LookupAccountName returns the S-1-5-99
    # (restricted services) form, sc.exe showsid prints the S-1-5-80 one.
    'restricted services\\printspoolerservice': 'S-1-5-99-216390572-1995538116-3857911515-2404958512-2623887229',
}

ONLY_RE = re.compile(r'\s*\((MS|DC) only\)\s*$', re.I)


def principals_from_title(title):
    """('Administrators, LOCAL SERVICE') -> friendly text, SID csv, unmapped[]"""
    title = ONLY_RE.sub('', title)
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


def category_for(section, groups):
    """Nearest enclosing benchmark group title, e.g. 18.10.42.13 -> 'Scan'."""
    parts = section.split('.')
    for i in range(len(parts) - 1, 0, -1):
        pref = '.'.join(parts[:i])
        if pref in groups:
            name = groups[pref]
            if i == 1:
                return name
            # qualify short/ambiguous leaf names with their parent
            parent = None
            for j in range(i - 1, 0, -1):
                p2 = '.'.join(parts[:j])
                if p2 in groups:
                    parent = groups[p2]
                    break
            if parent and len(name) < 24 and parent != name:
                return '%s - %s' % (parent, name)
            return name
    return groups.get(parts[0], 'CIS Benchmark')


TYPE_MAP = {'REG_DWORD': 'DWord', 'REG_SZ': 'String', 'REG_MULTI_SZ': 'MultiString',
            'REG_EXPAND_SZ': 'ExpandString', 'REG_QWORD': 'QWord', 'REG_BINARY': 'Binary'}

# Every rule in a Level 1 set is Level 1, so the CIS profile alone cannot rank
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


def parse_expect(expect, regtype):
    """Turn the PDF's 'expected value' phrase into (value, operator, absent_ok)."""
    e = re.sub(r'\s+', ' ', expect or '').strip().rstrip('.')
    absent_ok = False
    if re.match(r'^(?:that )?(?:the (?:value|key) )?does not exist$', e, re.I):
        return '', 'notexist', True
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
    m = re.match(r'^between (\d+) and (\d+)$', e, re.I)
    if m:
        return '%s,%s' % (m.group(1), m.group(2)), 'between', False
    m = re.match(r'^(\d+) for each (?:rule|entry|value)$', e, re.I)
    if m:
        return m.group(1), 'eq', False
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


# Field order of every generated policy record.
ORDER = ['Category', 'PolicyName', 'Scope', 'CheckType', 'PolicyPath', 'RegistryPath', 'SettingName',
         'ValueType', 'RecommendedValue', 'RecommendedSids', 'RequiredFlags', 'Operator',
         'AbsentIsCompliant', 'Priority', 'CisSection', 'CisLevel', 'CisBenchmark', 'Notes']


def ordered(records):
    return [{k: r[k] for k in ORDER if k in r} for r in records]
