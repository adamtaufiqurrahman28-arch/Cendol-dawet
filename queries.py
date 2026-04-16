from __future__ import annotations

from textwrap import dedent


ENCODED_POWERSHELL_TRIAGE = dedent(
    r'''
    #event_simpleName=ProcessRollup2 FileName=/powershell\.exe/i
    | CommandLine=/-enc(odedcommand)?/i
    | ProcKey := concat([aid, ":", TargetProcessId_decimal])

    // ===== ambil base64 blob + decode (PowerShell biasanya UTF-16LE) =====
    | regex("(?i)-enc(?:odedcommand)?\\s+(?<EncBlob>[A-Za-z0-9+/=]+)", field=CommandLine, strict=false)
    | case {
        EncBlob=* | base64decode(field=EncBlob, as=DecodedCmd, charset="UTF-16LE");
        *        | DecodedCmd := "";
      }

    // ===== DNS context (per process) =====
    | join(
        {
          #event_simpleName=DnsRequest
          | ProcKey := concat([aid, ":", ContextProcessId_decimal])
          | groupBy([ProcKey], function=[
              count(as=DnsCount),
              collect([DomainName], limit=10, separator=", ")
            ])
          | rename(field=DomainName, as=DnsDomains)
        },
        field=ProcKey,
        key=ProcKey,
        include=[DnsCount, DnsDomains],
        mode=left
      )

    // ===== Network context (per process) =====
    | join(
        {
          #event_simpleName=NetworkConnectIP4
          | ProcKey := concat([aid, ":", ContextProcessId_decimal])
          | Remote := concat([RemoteAddressIP4, ":", RemotePort])
          | groupBy([ProcKey], function=[
              count(as=NetConnCount),
              collect([Remote], limit=15, separator=", ")
            ])
          | rename(field=Remote, as=NetRemotes)
        },
        field=ProcKey,
        key=ProcKey,
        include=[NetConnCount, NetRemotes],
        mode=left
      )

    // ===== default hanya kalau field missing =====
    | case { DnsCount=*     | *; * | DnsCount := 0; }
    | case { NetConnCount=* | *; * | NetConnCount := 0; }
    | case { DnsDomains=*   | *; * | DnsDomains := ""; }
    | case { NetRemotes=*   | *; * | NetRemotes := ""; }

    // ===== FP/TP triage =====
    | case {

        DecodedCmd=/^\s*Set-Location\s+['"]C:\\['"]\s*$/i
          AND NOT (CommandLine=/invoke-expression|\biex\b|downloadstring|invoke-webrequest|\biwr\b|webclient|frombase64string/i
                   OR DecodedCmd=/invoke-expression|\biex\b|downloadstring|invoke-webrequest|\biwr\b|webclient|frombase64string/i)
          | Verdict := "LIKELY FALSE POSITIVE"
          | Severity := "LOW"
          | Reason := "Decoded command trivial (Set-Location), likely benign automation";

        (DecodedCmd=/invoke-expression|\biex\b|downloadstring|invoke-webrequest|\biwr\b|new-object\s+net\.webclient|frombase64string/i
          OR CommandLine=/invoke-expression|\biex\b|downloadstring|invoke-webrequest|\biwr\b|new-object\s+net\.webclient|frombase64string/i)
          | Verdict := "LIKELY TRUE POSITIVE"
          | Severity := "CRITICAL"
          | Reason := "Download/Execute or decode pattern";

        ParentBaseFileName=/winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe/i
          | Verdict := "LIKELY TRUE POSITIVE"
          | Severity := "HIGH"
          | Reason := "Office -> PowerShell EncodedCommand";

        ParentBaseFileName=/wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe|wmic\.exe/i
          | Verdict := "LIKELY TRUE POSITIVE"
          | Severity := "HIGH"
          | Reason := "LOLBIN parent -> PowerShell";

        (CommandLine=/-w(indowstyle)?\s+hidden\b/i
          OR CommandLine=/-executionpolicy\s+bypass\b/i
          OR CommandLine=/-ep\s+bypass\b/i)
          AND (NetConnCount > 0 OR DnsCount > 0)
          | Verdict := "LIKELY TRUE POSITIVE"
          | Severity := "HIGH"
          | Reason := "Stronger stealth flags + DNS/Network activity";

        ParentBaseFileName=/ccmexec\.exe|intunemanagementextension\.exe|pdqdeployrunner\.exe|salt-minion\.exe|tanium|bigfix/i
          AND NetConnCount = 0 AND DnsCount = 0
          AND NOT (DecodedCmd=/invoke-expression|\biex\b|downloadstring|invoke-webrequest|\biwr\b|webclient|frombase64string/i)
          | Verdict := "LIKELY FALSE POSITIVE"
          | Severity := "LOW"
          | Reason := "Mgmt/agent parent, no DNS/Net, no download/execute keywords";

        * | Verdict := "NEEDS REVIEW"
          | Severity := "MEDIUM"
          | Reason := "EncodedCommand detected but context not decisive";
      }

    | groupBy([ComputerName, UserName, ParentBaseFileName, FileName, Verdict, Severity, Reason, CommandLine, EncBlob], function=[
        count(as=Hits),
        min(@timestamp, as=FirstSeen),
        max(@timestamp, as=LastSeen),
        collect([DecodedCmd], limit=1, separator=" || "),
        collect([DnsDomains], limit=3, separator=" | "),
        collect([NetRemotes], limit=3, separator=" | ")
      ])
    | formatTime(field=FirstSeen, as=FirstSeen, format="%Y-%m-%d %H:%M:%S")
    | formatTime(field=LastSeen, as=LastSeen, format="%Y-%m-%d %H:%M:%S")
    | rename(field=DecodedCmd, as=SampleDecodedCmd)
    | rename(field=DnsDomains, as=SampleDomains)
    | rename(field=NetRemotes, as=SampleRemotes)
    | sort(LastSeen, order=desc)
    '''
).strip()

SSH_PROCESS_ACTIVITY = dedent(
    r'''
    #event_simpleName=ProcessRollup2
    | FileName=/^(ssh|sshd|scp|sftp)$/i
    | groupBy([ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], function=[
        count(as=Hits),
        min(@timestamp, as=FirstSeen),
        max(@timestamp, as=LastSeen)
      ])
    | formatTime(field=FirstSeen, as=FirstSeen, format="%Y-%m-%d %H:%M:%S")
    | formatTime(field=LastSeen, as=LastSeen, format="%Y-%m-%d %H:%M:%S")
    | sort(LastSeen, order=desc)
    '''
).strip()

NETWORK_CONNECTION_ACTIVITY = dedent(
    r'''
    #event_simpleName=NetworkConnectIP4
    | Remote := concat([RemoteAddressIP4, ":", RemotePort])
    | groupBy([ComputerName, ContextBaseFileName, LocalPort, Remote, Protocol], function=[
        count(as=Hits),
        min(@timestamp, as=FirstSeen),
        max(@timestamp, as=LastSeen)
      ])
    | formatTime(field=FirstSeen, as=FirstSeen, format="%Y-%m-%d %H:%M:%S")
    | formatTime(field=LastSeen, as=LastSeen, format="%Y-%m-%d %H:%M:%S")
    | sort(LastSeen, order=desc)
    '''
).strip()

SUSPICIOUS_DOWNLOADERS = dedent(
    r'''
    #event_simpleName=ProcessRollup2
    | FileName=/^(curl|wget|certutil|bitsadmin|powershell\.exe)$/i
    | CommandLine=/http|https|ftp|downloadstring|invoke-webrequest|\biwr\b/i
    | groupBy([ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], function=[
        count(as=Hits),
        min(@timestamp, as=FirstSeen),
        max(@timestamp, as=LastSeen)
      ])
    | formatTime(field=FirstSeen, as=FirstSeen, format="%Y-%m-%d %H:%M:%S")
    | formatTime(field=LastSeen, as=LastSeen, format="%Y-%m-%d %H:%M:%S")
    | sort(LastSeen, order=desc)
    '''
).strip()

PRESET_QUERIES: dict[str, dict[str, str]] = {
    "1": {
        "name": "Encoded PowerShell Triage",
        "lookback": "1d",
        "query": ENCODED_POWERSHELL_TRIAGE,
    },
    "2": {
        "name": "SSH Process Activity",
        "lookback": "1d",
        "query": SSH_PROCESS_ACTIVITY,
    },
    "3": {
        "name": "Network Connection Activity",
        "lookback": "12h",
        "query": NETWORK_CONNECTION_ACTIVITY,
    },
    "4": {
        "name": "Suspicious Downloaders",
        "lookback": "1d",
        "query": SUSPICIOUS_DOWNLOADERS,
    },
}
