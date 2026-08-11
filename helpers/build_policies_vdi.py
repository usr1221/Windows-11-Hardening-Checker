#!/usr/bin/env python3
r"""Derive Policies-VDI.json from Policies-CIS.json.

Every CIS check is reviewed for a NON-PERSISTENT (pooled, recomposed) VDI
desktop and gets one of four decisions:

  Keep       - applies unchanged
  Adjusted   - applies with a different value/operator (VDIRationale says why)
  Tolerant   - applies, but "value absent" is accepted because the feature may
               not be installed in an optimised image
  Excluded   - not applicable to a non-persistent virtual desktop; dropped from
               the JSON so it cannot skew the compliance score, and recorded in
               Policies-VDI-Decisions.csv with the reason

Writes Policies-VDI.json (the checks to run) and Policies-VDI-Decisions.csv
(every CIS check, including the excluded ones, with the reason).
"""
import csv
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths as P

CIS = json.load(open(P.POLICIES_CIS))

# --------------------------------------------------------------------------
# EXCLUDED - not applicable to a non-persistent virtual desktop
# --------------------------------------------------------------------------
EXCLUDE = {
    '18.9.35.6.1': 'Connected-standby on battery: a virtual desktop has no battery and no modern-standby power model, so this power setting never applies.',
    '18.9.35.6.2': 'Connected-standby plugged in: a virtual desktop has no modern-standby power model, so this power setting never applies.',
    '18.9.35.6.5': 'Wake-from-sleep password (on battery): pooled VMs do not sleep or hibernate - session security is enforced by the machine inactivity limit (2.3.7.3) and by the connection broker idle/disconnect timers.',
    '18.9.35.6.6': 'Wake-from-sleep password (plugged in): pooled VMs do not sleep or hibernate - session security is enforced by the machine inactivity limit (2.3.7.3) and by the broker idle/disconnect timers.',
    '18.9.5.6':    'Secure Launch (System Guard DRTM) requires physical platform DRTM support (Intel TXT / AMD SKINIT); no mainstream hypervisor exposes it to a guest, so the policy can never be satisfied on a VDI VM.',
    '18.10.43.1':  'Microsoft Defender Application Guard requires nested virtualisation and is deprecated/removed in current Windows 11 releases; it is not deployable on a pooled VDI desktop.',
    '18.10.43.2':  'Microsoft Defender Application Guard is not deployable on a pooled VDI desktop (nested virtualisation; deprecated feature).',
    '18.10.43.3':  'Microsoft Defender Application Guard is not deployable on a pooled VDI desktop (nested virtualisation; deprecated feature).',
    '18.10.43.4':  'Microsoft Defender Application Guard is not deployable on a pooled VDI desktop (nested virtualisation; deprecated feature).',
    '18.10.43.5':  'Microsoft Defender Application Guard is not deployable on a pooled VDI desktop (nested virtualisation; deprecated feature).',
    '18.10.43.6':  'Microsoft Defender Application Guard is not deployable on a pooled VDI desktop (nested virtualisation; deprecated feature).',
    '18.6.23.2.1': 'WLAN auto-connect to open hotspots: a virtual desktop has no wireless adapter and the WLAN service is removed by every VDI optimisation baseline.',
    '18.10.9.1.1': 'Biometric anti-spoofing applies to a physical IR camera; a pooled VM has no camera and Windows Hello face is not usable over a remoting protocol.',
    '18.10.80.1':  'Enhanced Sign-in Security requires supported physical biometric peripherals and a secure device path that a remoting protocol cannot provide.',
    '18.10.14.1':  'Miracast/Connect "require PIN for pairing" applies to wireless display projection, which is not available to a virtual desktop.',
    '18.10.92.1':  'Windows Sandbox requires nested virtualisation and is not installed in a VDI image.',
    '18.10.92.3':  'Windows Sandbox requires nested virtualisation and is not installed in a VDI image.',
    '18.10.94.1.1': 'Auto-restart with logged-on users only matters where the desktop installs updates itself; on a non-persistent pool updates come from the gold image and Windows Update is disabled (see 18.10.94.2.1).',
    '18.10.94.2.2': 'Scheduled install day is meaningless once automatic updates are turned off on the pooled desktop; patching happens in the gold image.',
    '18.10.94.4.1': 'Preview-build management is a gold-image decision; the pooled desktop does not service itself.',
    '18.10.94.4.2': 'Quality-update deferral is a gold-image / update-ring decision; the pooled desktop does not service itself.',
    '18.10.94.4.3': 'Optional-update control is a gold-image / update-ring decision; the pooled desktop does not service itself.',
    '2.3.6.5':      'Machine account maximum password age is superseded on a pooled desktop by disabling machine account password changes altogether (2.3.6.4) - a password change made after cloning is lost at recompose and breaks the domain trust.',
}

# --------------------------------------------------------------------------
# ADJUSTED - different value/operator for non-persistent VDI
#   section: (RecommendedValue, Operator, Priority|None, rationale)
# --------------------------------------------------------------------------
ADJUST = {
    '2.3.6.4': ('1', 'eq', 'Medium',
        'CIS requires machine account password changes to stay enabled (0). On a NON-PERSISTENT pool the '
        'new password is written to a disk that is discarded at logoff/recompose while AD keeps the changed '
        'password, which breaks the secure channel ("trust relationship failed"). Disable the change (1) on '
        'pooled desktops and let the gold image / provisioning system own the computer account. Persistent '
        '(dedicated) desktops should keep the CIS value of 0.'),
    '18.10.94.2.1': ('1', 'eq', 'Medium',
        'CIS requires Automatic Updates enabled (NoAutoUpdate=0). A non-persistent desktop discards anything '
        'it installs, and every VM in the pool downloading the same updates causes an I/O and bandwidth storm '
        'on the shared storage. Patch the gold image and set NoAutoUpdate=1 on the pooled desktop. If the pool '
        'is persistent, keep the CIS value of 0.'),
    '18.9.5.5': ('1,2', 'oneof', None,
        'CIS requires Credential Guard "Enabled with UEFI lock" (1). UEFI lock persists in the VM firmware '
        'and cannot be cleared without touching every VM, which conflicts with recompose/redeploy workflows; '
        '"Enabled without lock" (2) is accepted here. Credential Guard itself must stay on - it is the main '
        'defence against credential theft on a shared, multi-user desktop pool. Requires the hypervisor to '
        'expose nested virtualisation (Hyper-V nested virt, vSphere VBS, AVD/W365 Gen2).'),
    '18.9.5.3': ('1', 'eq', None,
        'Keep HVCI enabled, but note it only starts when the hypervisor exposes nested virtualisation and '
        'virtualisation-based security to the guest. Verify on one VM of the pool before enforcing pool-wide.'),
    '18.9.5.4': ('1', 'eq', 'Low',
        'CIS requires the UEFI Memory Attributes Table. Some hypervisors do not expose a MAT-capable virtual '
        'UEFI; where they do not, HVCI will refuse to start with this set to 1. Validate on the platform - if '
        'MAT is unavailable set it to 0 so HVCI can still run.'),
    '18.10.17.1': ('0,99', 'oneof', None,
        'CIS only forbids Download Mode 3 (Internet peering). For a VDI pool go further: peer-to-peer '
        'distribution between identical, short-lived VMs on the same host adds pointless disk and network I/O. '
        'Use 0 (HTTP only) or 99 (simple, no peering).'),
    '18.10.42.13.4': ('7', 'ge', 'Low',
        'Catch-up quick scan after N days: harmless but meaningless on a desktop that is rebuilt daily. '
        'Accept 7 or more. What matters on VDI is scan randomisation and the platform exclusions '
        '(disk images, provisioning agents) so the pool does not scan in lockstep.'),
}

# --------------------------------------------------------------------------
# TOLERANT - keep the check, but an absent value is acceptable
# --------------------------------------------------------------------------
TOLERANT_PREFIX = ('5.',)
TOLERANT_NOTE = ('VDI optimisation baselines (VMware OS Optimization Tool, Citrix Optimizer, the Microsoft '
                 'AVD image scripts) frequently remove this service outright. A service that is not installed '
                 'is at least as good as one that is disabled, so an absent Start value is accepted here.')

# --------------------------------------------------------------------------
# KEEP + implementation note
# --------------------------------------------------------------------------
NOTES = {
    '1.1.1': 'On a domain-joined pool these settings govern LOCAL accounts only; domain accounts follow the Default Domain Policy / PSOs.',
    '1.1.2': 'Local accounts on a pooled desktop are re-created from the image at every recompose, so the practical effect is limited to the image build.',
    '1.2.1': 'Lockout of local accounts only. Broker-side and AD lockout policy protect the accounts users actually log on with.',
    '2.2.5': 'VDI agents (Citrix VDA, Horizon Agent, AVD/RDS) require their service accounts to hold specific logon rights - verify the agent still starts after applying user-rights hardening.',
    '2.2.6': 'This is the right that governs broker-mediated RDP logon. Keep Remote Desktop Users populated by the pool assignment group, not by individual accounts.',
    '2.2.15': 'Denying "Local account" network logon blocks lateral movement between pool members with a shared local admin password - especially valuable when every VM comes from one image.',
    '2.2.19': 'Denying "Local account" RDS logon also blocks the break-glass local-admin RDP path; make sure an out-of-band console (hypervisor/broker) is available for support.',
    '2.3.1.3': 'Renaming must be done in the gold image - a rename applied to a running pooled VM is lost at recompose.',
    '2.3.1.4': 'Renaming must be done in the gold image - a rename applied to a running pooled VM is lost at recompose.',
    '2.3.7.3': 'Machine inactivity limit is the last line of defence; the broker idle/disconnect timers should trigger first so the session is disconnected rather than just locked.',
    '2.3.7.8': 'Only meaningful when smart cards are redirected into the session; verify the remoting protocol reports removal events, otherwise the session will never lock on card removal.',
    '2.3.10.7': 'Remote registry paths matter more on a pool: one exposed VM exposes the same configuration as every other VM built from the image.',
    '17.1.1': 'Local event logs are destroyed at logoff/recompose. Every audit subcategory below is only useful if the logs are forwarded (WEF/AMA/SIEM agent baked into the image) in near real time.',
    '18.4.2': 'SMBv1 client driver must be disabled in the gold image; a change made on a running pooled VM is discarded.',
    '18.6.4.1': 'mDNS/LLMNR/NetBIOS also generate constant broadcast noise between identical VMs on the same VLAN - disabling them helps the network as well as security.',
    '18.6.4.4': 'Disabling LLMNR removes a favourite lateral-movement/credential-relay path between pool members that all trust the same image.',
    '18.6.14.1': 'Hardened UNC paths are critical on VDI: the desktop pulls policy, scripts and often the profile container from SYSVOL/NETLOGON and file shares at every logon.',
    '18.9.5.1': 'VBS requires the hypervisor to expose nested virtualisation to the guest. Confirm on one pool member before enforcing; without it the VM boots with VBS off and every VBS check reports Mismatch.',
    '18.9.19.3': 'Processing GPOs even when unchanged matters on a pool - a freshly recomposed VM must apply the full policy set at first boot.',
    '18.9.19.5': 'Background refresh must stay on so policy changes reach long-lived sessions; stagger refresh intervals to avoid a pool-wide refresh storm.',
    '18.9.26.1': 'LAPS is only meaningful for PERSISTENT/dedicated desktops. On a non-persistent pool the local administrator password is reset from the image at every recompose, and each VM would churn a new AD/Entra password object per rebuild. Either exclude pooled VMs from LAPS scope or accept the churn deliberately.',
    '18.10.16.1': 'Diagnostic data limits also cut per-VM upload traffic; on a pool of hundreds of VMs this is a measurable saving.',
    '18.10.26.2.2': 'A 192 MB Security log per VM is a real cost on a differencing/writable layer. Size the writable disk for it, or reduce the local size ONLY if logs are forwarded off-box in near real time.',
    '18.10.42.10.3': 'Real-time protection must stay on, but the VDI platform paths (disk images, delta disks, provisioning and profile-container agents) must be excluded, and scheduled scans randomised, or the whole pool scans in lockstep and storage stalls.',
    '18.10.42.16': 'Defender on VDI additionally needs the vendor exclusions and scan randomisation from the Microsoft "Configure Defender Antivirus on a remote desktop or VDI environment" guidance.',
    '18.10.57.2.3': 'Applies to the Remote Desktop client running INSIDE the virtual desktop (nested RDP), not to the broker connection into it.',
    '18.10.57.3.3.3': 'Blocks drive redirection for RDP-based sessions. Citrix ICA/HDX and Omnissa/VMware Blast carry their own client-drive-mapping channel that this policy does NOT control - disable it in the vendor policy too, or the data path stays open.',
    '18.10.57.3.9.3': 'Security layer / NLA / encryption level apply to the RDP stack (AVD, W365, RDS-based pools). With Citrix or Horizon the equivalent controls live in the vendor policy set.',
    '18.10.57.3.11.1': 'Deleting temp folders on exit is doubly right on a pool: it limits data left in a session that other users may later be assigned to on a persistent pool, and reduces writable-layer growth.',
    '18.10.83.2': 'Automatic restart sign-on is irrelevant on a pooled desktop (it never restarts into a user session) but keeping it disabled prevents credential caching if a VM is converted to persistent.',
    '18.10.66.2': 'Store updates download per VM. In a pooled image the Store should be removed or fully policy-disabled so hundreds of VMs do not each pull the same packages.',
    '19.5.1.1': 'User-scope settings must arrive from GPO or the profile-container solution (FSLogix/App Layering); anything written into the image profile is lost when the profile container mounts.',
    '19.7.5.1': 'User-scope: deliver via GPO or the profile container, not by editing the default profile in the image.',
}
CATEGORY_NOTES = [
    (re.compile(r'^17\.'), 'Local event logs are lost at recompose - this subcategory only has value if events are forwarded off the VM.'),
]

# --------------------------------------------------------------------------
records, rows = [], []
for p in CIS:
    sec = p['CisSection']
    rec = dict(p)
    decision, rationale = 'Keep', ''

    if sec in EXCLUDE:
        decision, rationale = 'Excluded', EXCLUDE[sec]
        rows.append((sec, p['PolicyName'], p['Category'], decision,
                     p['RecommendedValue'], p['Operator'], '', '', rationale))
        continue

    if sec in ADJUST:
        val, op, prio, rationale = ADJUST[sec]
        decision = 'Adjusted' if (val != p['RecommendedValue'] or op != p['Operator']) else 'Keep'
        old = p['RecommendedValue']
        rec['RecommendedValue'], rec['Operator'] = val, op
        if prio:
            rec['Priority'] = prio
        rec['VDIRationale'] = rationale
        rows.append((sec, p['PolicyName'], p['Category'], decision,
                     old, p['Operator'], val, op, rationale))
    elif sec.startswith(TOLERANT_PREFIX):
        decision = 'Tolerant'
        rec['AbsentIsCompliant'] = True
        rec['VDIRationale'] = TOLERANT_NOTE
        rows.append((sec, p['PolicyName'], p['Category'], decision, p['RecommendedValue'], p['Operator'],
                     p['RecommendedValue'], p['Operator'] + ' (absent accepted)', TOLERANT_NOTE))
    else:
        note = NOTES.get(sec, '')
        if not note:
            for pat, txt in CATEGORY_NOTES:
                if pat.match(sec):
                    note = txt
                    break
        if note:
            rec['VDIRationale'] = note
        rows.append((sec, p['PolicyName'], p['Category'], decision, p['RecommendedValue'], p['Operator'],
                     p['RecommendedValue'], p['Operator'], note))

    rec['VDIDecision'] = decision
    records.append(rec)

ORDER = ['Category', 'PolicyName', 'Scope', 'CheckType', 'PolicyPath', 'RegistryPath', 'SettingName',
         'ValueType', 'RecommendedValue', 'RecommendedSids', 'RequiredFlags', 'Operator',
         'AbsentIsCompliant', 'Priority', 'CisSection', 'CisLevel', 'VDIDecision', 'VDIRationale', 'Notes']
json.dump([{k: r[k] for k in ORDER if k in r} for r in records],
          open(P.POLICIES_VDI, 'w'), indent=2, ensure_ascii=False)

with open(P.DECISIONS_CSV, 'w', newline='', encoding='utf-8-sig') as fh:
    w = csv.writer(fh)
    w.writerow(['CIS Section', 'Policy Name', 'Category', 'VDI Decision',
                'CIS Recommended Value', 'CIS Operator',
                'VDI Recommended Value', 'VDI Operator', 'VDI Rationale / Note'])
    for r in rows:
        w.writerow(r)

import collections
print('wrote', os.path.relpath(P.POLICIES_VDI, P.REPO), 'and', os.path.relpath(P.DECISIONS_CSV, P.REPO))
print('CIS checks   :', len(CIS))
print('VDI checks   :', len(records))
print(collections.Counter(r[3] for r in rows))
