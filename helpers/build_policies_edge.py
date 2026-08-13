#!/usr/bin/env python3
r"""Build Policies-Edge.json from the Microsoft Edge security baseline.

Two inputs, with a clear order of authority:

  *.PolicyRules  - the Policy Analyzer export of the baseline GPO. This is the
                   AUTHORITY for the registry key, value name, type and data,
                   because it is a mechanical dump of the baseline's
                   registry.pol.
  *.xlsx         - the converted audit report. Used only to cross-check that
                   the two describe the same setting set, and as the seed for
                   the short rationale in Notes.

Everything else (friendly policy name, the Administrative Templates path,
priority, the expanded note) is curated in META below, because neither input
carries it: the .PolicyRules file has only raw registry data, and the xlsx
falls back to the value name when the converter cannot resolve a friendly
name.

Writes Policies-Edge.json in the repository root.
"""
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths as P

EDGE_KEY = r'Software\Policies\Microsoft\Edge'
ADMX = r'Computer Configuration\Policies\Administrative Templates\Microsoft Edge'

# --------------------------------------------------------------------------
# Curated metadata, keyed by registry value name.
#   (Category, PolicyName, PolicyPath suffix, Priority, Notes)
#
# PolicyName / PolicyPath are transcribed from the Edge ADMX templates so the
# report is readable by someone who has to find the setting in gpedit. They are
# labels only - the check itself is driven by RegistryPath + SettingName, which
# come from the .PolicyRules file.
# --------------------------------------------------------------------------
META = {
    'SitePerProcess': (
        'Isolation', 'Enable site isolation for every site', '', 'High',
        'Forces every site into its own renderer process. Without it a renderer compromised through a '
        'browser exploit can read cross-origin data that happens to share its process, which is the '
        'foundation of Spectre-class and universal-XSS attacks. This is the single most valuable Edge '
        'hardening setting and it cannot be turned off by the user once enforced. Cost: more processes '
        'and therefore more RAM per session - the one baseline setting with a real footprint on a VDI '
        'host, where session density is the constraint. Budget for it rather than dropping it.'),
    'AuthSchemes': (
        'Authentication', 'Supported authentication schemes', r'\HTTP authentication', 'High',
        'Restricts Edge to NTLM and Negotiate, removing Basic and Digest. Basic transmits credentials '
        'reversibly encoded, and both are accepted by attacker-controlled servers that prompt for them, '
        'so removing the schemes removes the prompt. Note the check compares the string exactly as the '
        'baseline writes it - "negotiate,ntlm" is functionally identical but will be reported as a '
        'Mismatch, so normalise on the baseline ordering rather than loosening the check.'),
    'NativeMessagingUserLevelHosts': (
        'Extensions', 'Allow user-level native messaging hosts (installed without admin permissions)',
        r'\Native Messaging', 'High',
        'Blocks native-messaging hosts registered under HKCU. A native-messaging host is an arbitrary '
        'local executable an extension may invoke, and the per-user variant needs no administrator '
        'rights to register - which makes it a favourite persistence and privilege-bridge channel for '
        'malicious or hijacked extensions. Only admin-installed (HKLM) hosts remain usable.'),
    'SmartScreenEnabled': (
        'SmartScreen', 'Configure Microsoft Defender SmartScreen', r'\SmartScreen settings', 'High',
        'Turns on SmartScreen reputation checks for sites and downloads. Requires outbound connectivity '
        'to the SmartScreen service - on a locked-down or proxied desktop pool, verify the endpoints are '
        'reachable, because a blocked SmartScreen fails open and this registry check still reports '
        'Configured.'),
    'PreventSmartScreenPromptOverride': (
        'SmartScreen', 'Prevent bypassing Microsoft Defender SmartScreen prompts for sites',
        r'\SmartScreen settings', 'High',
        'Removes the "continue anyway" path on a SmartScreen site warning. Without it the block is '
        'advisory, and phishing pretexts routinely coach the user through exactly that click.'),
    'PreventSmartScreenPromptOverrideForFiles': (
        'SmartScreen', 'Prevent bypassing of Microsoft Defender SmartScreen warnings about downloads',
        r'\SmartScreen settings', 'High',
        'The download-warning counterpart of PreventSmartScreenPromptOverride. Stops the user keeping a '
        'file SmartScreen flagged as malicious or unusually rare - the last gate before an initial-access '
        'payload reaches disk.'),
    'SSLErrorOverrideAllowed': (
        'Transport security', 'Allow users to proceed from the HTTPS warning page', '', 'High',
        'Removes the "Advanced -> proceed to (unsafe)" link on certificate errors. That link is what '
        'turns a detected TLS interception into a successful one. Inventory internal sites with expired '
        'or self-signed certificates before enforcing - after this, they become unreachable rather than '
        'click-through, which is the point, but it is a helpdesk event if you have not fixed them first.'),
    'SmartScreenPuaEnabled': (
        'SmartScreen', 'Configure Microsoft Defender SmartScreen to block potentially unwanted apps',
        r'\SmartScreen settings', 'Medium',
        'Extends SmartScreen to potentially unwanted applications - bundleware, adware and the '
        'download-portal wrappers that are a common first stage. Pairs with the Defender PUA setting '
        '(CIS 18.10.42.16); both are needed since they act at different points.'),
    'BasicAuthOverHttpEnabled': (
        'Authentication', 'Allow Basic authentication for HTTP', r'\HTTP authentication', 'High',
        'Blocks Basic authentication over cleartext HTTP even where the scheme is otherwise permitted. '
        'Defence in depth behind AuthSchemes: covers the case where an internal site still negotiates '
        'Basic and would send credentials in a trivially recoverable header.'),
    'InternetExplorerIntegrationReloadInIEModeAllowed': (
        'IE mode', 'Allow unconfigured sites to be reloaded in Internet Explorer mode', '', 'High',
        'Stops users reloading arbitrary sites into IE mode. IE mode runs MSHTML, the legacy engine with '
        'ActiveX and a far weaker sandbox, so a user-initiated reload is an attacker-reachable downgrade '
        'to a decade-old attack surface. Sites that genuinely need IE mode belong on the Enterprise Mode '
        'Site List, which this does not affect.'),
    'SharedArrayBufferUnrestrictedAccessAllowed': (
        'Isolation', 'Specifies whether SharedArrayBuffers can be used in a non cross-origin-isolated context',
        '', 'Medium',
        'Requires cross-origin isolation before a page may use SharedArrayBuffer. SharedArrayBuffer '
        'provides the high-resolution timer primitive that makes Spectre-class side channels practical '
        'from script; gating it on cross-origin isolation removes that primitive from ordinary pages. '
        'Complements SitePerProcess rather than duplicating it.'),
    'BrowserLegacyExtensionPointsBlockingEnabled': (
        'Process hardening', 'Enable browser legacy extension point blocking', '', 'High',
        'Blocks the legacy in-process injection points - AppInit_DLLs, Winsock LSPs, IME and window '
        'hooks - from loading third-party code into Edge processes. Watch for legacy accessibility '
        'tools, DLP shims and some Citrix/VDI browser-redirection helpers that still inject this way; '
        'test the browser-content-redirection path if you use it.'),
    'InternetExplorerModeToolbarButtonEnabled': (
        'IE mode', 'Show the Reload in Internet Explorer mode button in the toolbar', '', 'Medium',
        'Removes the toolbar affordance for IE mode. Weaker than '
        'InternetExplorerIntegrationReloadInIEModeAllowed, which actually blocks the action - this only '
        'removes the button - but it closes the social-engineering script that tells a user which button '
        'to press.'),
    'TyposquattingCheckerEnabled': (
        'SmartScreen', 'Configure Edge TyposquattingChecker', '', 'Medium',
        'Warns when a navigated domain closely resembles a well-known one. Aimed squarely at '
        'credential-phishing pretexts built on look-alike domains. Advisory rather than blocking, so it '
        'supplements SmartScreen rather than replacing it.'),
    'InternetExplorerIntegrationZoneIdentifierMhtFileAllowed': (
        'IE mode', 'Allow MHT files to be opened in Internet Explorer mode based on the Zone Identifier',
        '', 'Medium',
        'Stops a downloaded .mht/.mhtml archive from opening itself in IE mode based on its zone marking. '
        'MHT is a mail-friendly single-file format that survives gateways, which makes this a practical '
        'delivery route into MSHTML; blocking it closes an attachment-driven path to the same legacy '
        'engine that the IE-mode settings above cover for navigation.'),
    'DynamicCodeSettings': (
        'Process hardening', 'Dynamic Code Settings', '', 'High',
        'Enables Arbitrary Code Guard for Edge processes: pages may not allocate executable memory or '
        'change existing pages to executable. This is what turns a browser memory-corruption bug from '
        'code execution into a crash, so it is the highest-value exploit mitigation in the baseline '
        'after site isolation. It does not need VBS or nested virtualisation - it is a per-process '
        'mitigation policy, so it works normally on a Citrix/XenServer VM.'),
    'ApplicationBoundEncryptionEnabled': (
        'Credential protection', 'Application Bound Encryption Settings', '', 'High',
        'Binds Edge cookie and password encryption to Edge itself, so another process running as the '
        'same user cannot simply call DPAPI to decrypt the vault. This is the direct counter to the '
        'modern infostealer pattern (Lumma, RedLine and successors) and it matters more on a shared '
        'desktop pool, where any one compromised session sits alongside other users on the same host.'),
    'EnableUnsafeSwiftShader': (
        'Process hardening', 'Enable the unsafe SwiftShader fallback', '', 'Medium',
        'Disables the SwiftShader software GPU fallback, a large C++ rasteriser reachable from WebGL '
        'content and a repeated source of exploitable bugs. Relevant on VDI specifically: virtual '
        'desktops usually have no GPU, so they are exactly the machines that fall back to SwiftShader. '
        'Expect WebGL-dependent sites to degrade or fail on a vGPU-less pool - that is the trade, and '
        'if you need WebGL the answer is a vGPU, not re-enabling this.'),
}

# Extension blocklist lives under a subkey and is a list-style policy.
BLOCKLIST = (
    'Extensions', 'Control which extensions cannot be installed', r'\Extensions', 'High',
    'Entry "1" set to "*" blocks every extension that is not explicitly permitted by '
    'ExtensionInstallAllowlist or ExtensionInstallForcelist. This is a default-deny, so it is the one '
    'baseline setting that will visibly break things if rolled out without an allowlist first: inventory '
    'the extensions actually in use, allowlist them, then enforce. On a non-persistent pool, remember '
    'user-installed extensions are discarded at recompose anyway - anything users need must be '
    'force-installed from the image or by policy.')


def read_policyrules(path):
    root = ET.fromstring(open(path, encoding='utf-8-sig').read())
    out = []
    for node in root:
        if node.tag != 'ComputerConfig':
            continue                      # CSE-Machine is GPO plumbing, not a setting
        d = {c.tag: (c.text or '') for c in node}
        out.append(d)
    return out


def read_xlsx(path):
    """Return {setting name: short note} from the converted audit report."""
    ns = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
    z = zipfile.ZipFile(path)
    shared = []
    if 'xl/sharedStrings.xml' in z.namelist():
        for si in ET.fromstring(z.read('xl/sharedStrings.xml')):
            shared.append(''.join(t.text or '' for t in si.iter(ns + 't')))

    # The detail sheet is the one whose first row starts with "Category".
    for name in sorted(n for n in z.namelist() if n.startswith('xl/worksheets/sheet')):
        rows = []
        for r in ET.fromstring(z.read(name)).iter(ns + 'row'):
            cells = []
            for c in r.findall(ns + 'c'):
                v = c.find(ns + 'v')
                if v is None:
                    cells.append('')
                elif c.get('t') == 's':
                    cells.append(shared[int(v.text)])
                else:
                    cells.append(v.text)
            rows.append(cells)
        if rows and rows[0] and rows[0][0] == 'Category':
            head = rows[0]
            iname, inote = head.index('Setting name'), head.index('Notes')
            return {r[iname]: r[inote] for r in rows[1:] if len(r) > inote}
    return {}


def main():
    ap = P.parser(__doc__)
    ap.add_argument('--rules', default=None, help='Policy Analyzer .PolicyRules export')
    ap.add_argument('--xlsx', default=None, help='converted audit report (.xlsx)')
    args = ap.parse_args()

    rules_path = args.rules or P.find_one('*Edge*.PolicyRules', 'Edge .PolicyRules baseline')
    xlsx_path = args.xlsx or P.find_one('*edge*.xlsx', 'Edge audit .xlsx')

    entries = read_policyrules(rules_path)
    seeds = read_xlsx(xlsx_path)
    baseline = entries[0].get('PolicyName', '') if entries else ''

    records, skipped, warnings = [], [], []
    for d in entries:
        key, name = d['Key'], d['Value']

        # "**delvals." is a registry.pol directive telling the Group Policy
        # client to clear the key before writing, not a value that ever exists
        # on disk. Auditing it would report Not Configured forever.
        if name.startswith('**'):
            skipped.append('%s\\%s (registry.pol directive, never present on disk)' % (key, name))
            continue

        if key.rstrip('\\').lower() == EDGE_KEY.lower():
            if name not in META:
                warnings.append('no curated metadata for %s - add it to META' % name)
                continue
            cat, pol, sub, prio, notes = META[name]
            policy_path = ADMX + sub
        elif key.lower().endswith(r'\extensioninstallblocklist'):
            cat, pol, sub, prio, notes = BLOCKLIST
            policy_path = ADMX + sub
            pol = '%s (entry %s)' % (pol, name)
        else:
            warnings.append('unrecognised key %s\\%s' % (key, name))
            continue

        if name in seeds and seeds[name] and seeds[name] not in notes:
            notes = '%s Report summary: %s' % (notes, seeds[name])

        records.append({
            'Category': cat,
            'PolicyName': pol,
            'Scope': 'Computer',
            'CheckType': 'Registry',
            'PolicyPath': policy_path,
            'RegistryPath': 'HKLM\\' + key,
            'SettingName': name,
            'ValueType': {'REG_DWORD': 'DWord', 'REG_SZ': 'String',
                          'REG_MULTI_SZ': 'MultiString'}.get(d.get('RegType'), 'String'),
            'RecommendedValue': d.get('RegData', ''),
            'Operator': 'eq',
            'AbsentIsCompliant': False,
            'Priority': prio,
            'Baseline': baseline,
            'Notes': '%s. %s' % (baseline, notes),
        })

    # Cross-check: every setting the report assessed should be covered.
    missing = [n for n in seeds
               if n not in {r['SettingName'] for r in records}
               and not n.startswith('(')]
    for n in missing:
        warnings.append('in the xlsx but not produced: %s' % n)

    records.sort(key=lambda r: (r['Category'], r['SettingName']))
    json.dump(records, open(P.POLICIES_EDGE, 'w'), indent=2, ensure_ascii=False)

    print('policyrules :', os.path.basename(rules_path))
    print('xlsx        :', os.path.basename(xlsx_path))
    print('baseline    :', baseline)
    print('wrote', os.path.relpath(P.POLICIES_EDGE, P.REPO), '- records:', len(records))
    for s in skipped:
        print('  skipped:', s)
    for w in warnings:
        print('  WARNING:', w)


if __name__ == '__main__':
    main()
