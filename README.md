# AD Audit Trail

A single self-contained `ADAudit.exe` for Active Directory. The same exe does three jobs:

| Role | Where | Runs as | What it does |
|---|---|---|---|
| **Service** (`--service`, Windows service "AD Audit Trail") | **one DC** | **LocalSystem** | Collects the Security log of **all** DCs and imports past events. Writes the append-only, hash-chained trail, links reverts, and enforces the group alert / auto-removal rules. |
| **Viewer on the DC** (`ADAudit.exe`) | the DC with the service | Administrator (UAC) | Dashboard and audit log, read through a local pipe. |
| **Viewer on admin PCs** (`ADAudit.exe`, installed with `--install-viewer`) | any domain-joined admin PC | Administrator (UAC) | Same UI with **no local database**. Reads the trail live from the DC's service over the network, using your account or Domain Admin credentials you enter. |

## The viewer

The viewer has two pages, switched in the left navigation rail.

**Dashboard**
- Stat cards: directory changes, group membership changes, created/deleted objects, reverted changes, security events, alerts/tampering.
- An activity chart over time (hover a point for the exact numbers) and a breakdown by category.
- **Similar events, grouped**: the same action by the same person on the same attribute becomes one row. For example "10× Member added to group · CORP\adm.novak · 7 objects · ↩ 2 reverted". Double-click a row to open its individual entries in the log.

**Audit log**
- Full-text search: every word must match, `"phrase"`, `-exclude`, `#123` jumps to an entry.
- Time range (presets or custom), category chips, DC filter, *Reverted only*, live updates, CSV export.
- A details pane showing who, what, when, where, the old and new values, the raw event, the hash and the revert links.

The top bar shows each DC's collection status, the service's memory use, and the result of the integrity check.

## What gets recorded

Each entry has the following fields:

- **Who**: the account that made the change, or `SYSTEM (DC01)` when the server itself did it.
- **What**: the target DN, class and GUID, plus the attribute with its old and new values.
- **When**: local time and UTC.
- **From where**: client host and IP, from the 4624 logon event of the actor's session.
- **On which DC** the change was made.
- **Revert links**:
  - added ↔ removed
  - A→B ↔ B→A
  - created ↔ deleted
  - deleted ↔ restored
  - moved ↔ moved back

Sources:

- Security events from both DCs: 5136–5141 (AD object changes), 4723/4724 (password), 4740/4767 (lockout), 4719 (audit policy), 4794 (DSRM), 1102 (**log cleared**).
- The service's own entries:
  - service start/stop
  - group alerts, acknowledgments and removals
  - lost records
  - **every viewer session**: who opened the trail, and from which computer

**No duplicates:** each DC only logs changes that originate on it, and every record has a unique key. Imported history is matched against existing entries before it is added.

## Initialization: past events on first install

On first start the service works through two phases. Progress shows in the viewer as a banner, and live monitoring runs during both.

1. **Security log back-fill**: everything still present in the Security logs of **both** DCs is imported with full detail: who, from where, old and new value. How far back this reaches depends on log size, typically days to weeks.
2. **AD history reconstruction, covering the last 6 months**: AD's own replication metadata is read for every object changed in the period:
   - **objects created** (`whenCreated`)
   - **objects deleted** (tombstones in *Deleted Objects*, including their original location)
   - **group members added and removed**, with the exact time of each (`msDS-ReplValueMetaData`)
   - **the last change of every attribute**, with its time, originating DC and current value (`msDS-ReplAttributeMetaData`)

   These entries are marked **"reconstructed"**. AD does not store *who* made a change or *from where*, and only keeps the *last* change per attribute, so the actor shows as "(unknown – before ADAudit)". Changes that phase 1 already imported are skipped.

From then on everything is recorded live with full detail. Set `"ReconstructHistory": false` to skip phase 2.

## Lightweight by design

- **No log re-scanning.** The collector seeks directly to its bookmark in each DC's Security log every 15 s, so a poll only touches the records written since the last poll. The "from where" lookup searches backwards from the change event itself, and results are cached.
- **Low priority.** The service process runs at *BelowNormal* priority, and the collector thread uses Windows *background mode* (lowest CPU, disk-I/O and memory priority). It never competes with LSASS or NTDS. The initial import is paced in small batches with pauses.
- **Small memory footprint.**
  - The service never loads the UI libraries.
  - The GC runs in conserve-memory mode, with a 4 MB SQLite cache.
  - The exe is mapped into memory, not unpacked into RAM.
  - The viewer shows the service's current RAM use (the "Service" pill).
- **Cheap integrity checks.** Viewers trigger incremental checks of new entries only. A full re-check runs every 6 h in the background, or when you click **Verify**.

## Group alerts and automatic removal (Settings)

Open the **gear icon** in the viewer's navigation rail. Settings are stored by the service on the DC and take effect immediately. **Every change is itself recorded in the audit trail** with who, from where, and the old → new values.

Each rule has a group, *Alert* on/off, *Acknowledge* on/off, and *Remove new member* on/off with a time in minutes.

| Group | Alert | Acknowledge | Removed? |
|---|---|---|---|
| **Domain Admins** (default) | yes | required | **no, never removed** |
| *your maintenance group* (example, add it yourself) | yes | off | yes, after e.g. 60 min |

The Domain Admins rule matches by RID 512, so it works with localized names such as "Domänen-Admins".

A typical extra rule is a **temporary admin group** that should normally be empty: people are added for maintenance work and removed automatically after an hour. For such groups (any group with *Remove new member* on), an addition is always shown as a new event, and only the removal counts as its revert.

When a member is added to a group with a rule:

1. **Alert**: an Application event log warning (source `ADAudit`, ID 1001), a pop-up in every session on the DC (can be switched off), and optionally email. A banner appears in every viewer: red with a countdown for a removal, amber for alert-only.
2. **Removal** (only where switched on): over LDAP on the local DC, running as SYSTEM, using the member's SID.
   - The removal is linked as the revert of the addition.
   - If you switch removal off before the deadline, the scheduled removal is cancelled, and the cancellation is recorded.

Additions found in historic data from before the install only ever alert.

**Acknowledge (per group, default on for Domain Admins):**
- Alerts for the group stay open, in an amber banner, until someone clicks **Acknowledge** and enters a reason.
- The membership is then remembered as intended and does not alert again for that person in that group. It's matched by SID, so renames don't matter.
- Acknowledged memberships are listed in Settings and can be **revoked**.
- Acknowledging, revoking and every settings change are recorded in the audit trail: who, when, from where and the reason. Acknowledging a pending removal cancels the removal.

**E-mail:** configure mail server, port, TLS, user name, password, sender and recipients in Settings, and use **Send test mail** to check them.
- The mail is sent by the service on the DC.
- The password is stored DPAPI-encrypted on the DC and is never shown or sent back to a viewer.

## Readable values and less noise

- **Readable values.** Raw values are shown in readable form:
  - `primaryGroupID 513` shows as "CORP\Domain Users (513)".
  - SIDs show as account names.
  - Account flags, group types and encryption types are decoded.
  - FILETIMEs show as dates, and GPO GUIDs and links show the GPO name.

  The stored record stays untouched; the names are added when entries are shown.
- **Not recorded, because no person changed anything:**
  - **no-op writes**, where the same value is written again (e.g. ADUC re-writing `primaryGroupID`); these are never linked as "reverts" either.
  - **computers maintaining their own attributes**: SPN, DNS host name, OS version, encryption types, certificate.
  - **dynamic DNS updates**.

  Security-relevant self-writes are always kept: delegation, key credentials, account flags.
- **Older noise.** Entries stored before this filter existed are hidden by default. Tick **System noise** in the log to show them.

## Viewer: log table

- **Resize columns** by dragging the header edges. The handle lights up on hover. Widths are remembered per user.
- **Selected row:** a teal highlight with a ring around its timeline dot.
- **Timeline on the left:** a coloured trail with a dot per event, in the category colour. Hollow dots are reconstructed entries.
- **Revert connectors:** a slim amber bracket connects a change with the change that reverted it (e.g. *member added to a group* → *member removed*). The arrow points at the revert.

## Immutability – what is guaranteed, what is not

- **Append-only.** Triggers reject every `UPDATE`, and every `DELETE` of entries younger than 183 days. Revert links are immutable too.
- **HMAC-SHA256 hash chain.** Any edited, removed or reordered entry is reported as **TAMPERED** together with its entry ID.
  - The key is DPAPI-encrypted and readable by SYSTEM only.
  - The chain head is written to the Application event log every hour.
- **Read-only access paths.** The data folder `C:\ProgramData\ADAudit` is SYSTEM: full control, Administrators: read-only, and the service re-applies this at every start. The pipe protocol (local and remote) only offers **read** operations.
- **Hardened service.** Administrators cannot stop or delete the service without first changing its security descriptor, and that change is logged.
- **Honest limit:** a Domain Admin with full control of the DC can still destroy local data. That is *detectable*, not *impossible*. For tamper-proof storage, also forward the Security log and the `ADAudit` events to a SIEM or WORM store.

## Build

Requires the .NET 10 SDK.

```powershell
dotnet publish .\ADAudit\ADAudit.csproj -c Release -o .\dist
```

The output is `dist\ADAudit.exe`, a single self-contained file. Neither the DC nor the PCs need .NET installed.

- **UI preview** with sample data:
  ```powershell
  dotnet run --project .\ADAudit\ADAudit.csproj -p:RequireAdmin=false -- --demo
  ```
  When switching between `RequireAdmin=false` and the normal build, delete `ADAudit\bin` and `ADAudit\obj` first.
- **Storage self-test** on a throw-away database (16 checks: duplicates, revert linking, rejected UPDATE/DELETE, tamper detection, duplicate detection for imported history, dashboard aggregation):
  ```powershell
  .\ADAudit.exe --selftest
  ```

## Install

### On one DC (as Domain Admin)

```powershell
.\ADAudit.exe --install
```

The installer:

1. Copies the exe to `C:\Program Files\ADAudit\` and creates the locked-down data folder.
2. Creates the service **"AD Audit Trail"** as **LocalSystem** (delayed auto-start, restarts on failure) and hardens its permissions.
3. Adds audit SACLs on the domain partition, the Configuration partition and AdminSDHolder. SACLs replicate, so both DCs are covered.
4. Adds **Domain Controllers** to **Event Log Readers**, so this DC can read the other DC's Security log.
5. On **every DC** (the other one via PowerShell remoting):
   - enables the audit subcategories
   - sets the Security log to 1 GB
   - enables the firewall group *Remote Event Log Management*
6. Creates a Start menu shortcut and starts the service. Initialization begins immediately.

### On admin PCs (viewer only, no database)

```powershell
.\ADAudit.exe --install-viewer
```

This copies the exe and creates a Start menu shortcut. Nothing else.

When the viewer starts, it looks for the service in this order:
1. the local service, if this machine is the DC
2. the last DC it used
3. every DC of the domain

If your logged-on account has no rights on the DC, use **"Use other credentials…"** on the connect screen and enter your Domain Admin account in the standard Windows credential dialog:
- The credentials are used **for this connection only**, like `runas /netonly`.
- No interactive logon happens on the PC.
- Nothing is stored. The viewer only remembers the last DC name, in `%APPDATA%\ADAudit\viewer.json`.

To skip the search: `ADAudit.exe --server DC01`.

**Network details:**
- The viewer connects to `\\<DC>\pipe\ADAudit.v1` over SMB (TCP 445, already open on every DC), authenticated with Kerberos.
- Access is limited to **Administrators of the DCs** (Domain Admins, Enterprise Admins, built-in Administrators), plus any `ViewerGroups` you configure.
- DCs require SMB signing by default, so the data can't be altered in transit. To also encrypt it, enable SMB encryption on the DCs:
  ```powershell
  Set-SmbServerConfiguration -EncryptData $true
  ```
- Set `"AllowRemoteViewers": false` to allow local viewing on the DC only.

Uninstall either kind of install with `ADAudit.exe --uninstall`. On the DC the audit database is **kept** on purpose.

### Manual configuration (if an installer step fails)

- **Audit policy via GPO (recommended):** in the *Default Domain Controllers Policy*, under Advanced Audit Policy, set:
  - DS Access → Directory Service Changes: Success
  - Logon/Logoff → Logon: Success
  - Account Management → User Account Management: Success, Failure
  - Account Logon → Account Lockout: Success
  - Policy Change → Audit Policy Change: Success

  If this GPO already defines advanced audit settings, it overrides `auditpol`.
- **Remote log access:** the other DC needs the firewall group *Remote Event Log Management*, and Domain Controllers must be in *Event Log Readers*. Afterwards run `klist -li 0x3e7 purge` on the collecting DC.
- **SACL:** in ADSI Edit, open the domain root → Security → Advanced → Auditing. Add *Everyone*, Success, *This object and all descendant objects*, with write/delete/create/permission rights.

## Configuration – `C:\ProgramData\ADAudit\config.json` (on the DC)

Administrators can edit this file. Restart the service afterwards. The file's SHA-256 is recorded in the trail at every start.

```json
{
  "PollSeconds": 15,
  "RetentionDays": 183,
  "DomainControllers": [],
  "AllowRemoteViewers": true,
  "ViewerGroups": [ "CORP\\AD-Audit-Readers" ],
  "ReconstructHistory": true,
  "GuardedGroups": [
    { "Name": "Domain Admins", "DomainRid": 512, "Alert": true, "RequireAck": true, "AutoRemove": false },
    { "Name": "Maint_Admins", "Alert": true, "RequireAck": false, "AutoRemove": true, "MaxMembershipMinutes": 60 }
  ],
  "EnforceGuardOnBackfill": false,
  "PopupAlerts": true,
  "Smtp": { "Host": "smtp.corp.local", "Port": 25, "UseSsl": false, "From": "adaudit@corp.local", "To": [ "it-security@corp.local" ] },
  "IgnoredAttributes": [ "lastLogonTimestamp", "badPwdCount", "..." ]
}
```

- `DomainControllers`: leave empty to auto-discover.
- `ViewerGroups`: optional read-only viewers in addition to DC administrators.

Logs: `C:\ProgramData\ADAudit\logs\service.log`. For troubleshooting, stop the service and run `ADAudit.exe --console`.
