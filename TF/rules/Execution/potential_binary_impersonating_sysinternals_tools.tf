resource "azurerm_sentinel_alert_rule_scheduled" "potential_binary_impersonating_sysinternals_tools" {
  name                       = "potential_binary_impersonating_sysinternals_tools"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Binary Impersonating Sysinternals Tools"
  description                = "Detects binaries that use the same name as legitimate sysinternals tools to evade detection. This rule looks for the execution of binaries that are named similarly to Sysinternals tools. Adversary may rename their malicious tools as legitimate Sysinternals tools to evade detection."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\accesschk64a.exe" or FolderPath endswith "\\ADExplorer64a.exe" or FolderPath endswith "\\ADInsight64a.exe" or FolderPath endswith "\\adrestore64a.exe" or FolderPath endswith "\\Autologon64a.exe" or FolderPath endswith "\\Autoruns64a.exe" or FolderPath endswith "\\autorunsc64a.exe" or FolderPath endswith "\\Clockres64a.exe" or FolderPath endswith "\\Contig64a.exe" or FolderPath endswith "\\Coreinfo64a.exe" or FolderPath endswith "\\Dbgview64a.exe" or FolderPath endswith "\\disk2vhd64a.exe" or FolderPath endswith "\\diskext64a.exe" or FolderPath endswith "\\DiskView64a.exe" or FolderPath endswith "\\du64a.exe" or FolderPath endswith "\\FindLinks64a.exe" or FolderPath endswith "\\handle64a.exe" or FolderPath endswith "\\hex2dec64a.exe" or FolderPath endswith "\\junction64a.exe" or FolderPath endswith "\\LoadOrd64a.exe" or FolderPath endswith "\\LoadOrdC64a.exe" or FolderPath endswith "\\logonsessions64a.exe" or FolderPath endswith "\\movefile64a.exe" or FolderPath endswith "\\notmyfault64a.exe" or FolderPath endswith "\\notmyfaultc64a.exe" or FolderPath endswith "\\pendmoves64a.exe" or FolderPath endswith "\\pipelist64a.exe" or FolderPath endswith "\\procdump64a.exe" or FolderPath endswith "\\procexp64a.exe" or FolderPath endswith "\\Procmon64a.exe" or FolderPath endswith "\\PsExec64a.exe" or FolderPath endswith "\\psfile64a.exe" or FolderPath endswith "\\PsGetsid64a.exe" or FolderPath endswith "\\PsInfo64a.exe" or FolderPath endswith "\\pskill64a.exe" or FolderPath endswith "\\psloglist64a.exe" or FolderPath endswith "\\pspasswd64a.exe" or FolderPath endswith "\\psping64a.exe" or FolderPath endswith "\\PsService64a.exe" or FolderPath endswith "\\pssuspend64a.exe" or FolderPath endswith "\\RAMMap64a.exe" or FolderPath endswith "\\RegDelNull64a.exe" or FolderPath endswith "\\ru64a.exe" or FolderPath endswith "\\sdelete64a.exe" or FolderPath endswith "\\sigcheck64a.exe" or FolderPath endswith "\\streams64a.exe" or FolderPath endswith "\\strings64a.exe" or FolderPath endswith "\\sync64a.exe" or FolderPath endswith "\\Sysmon64a.exe" or FolderPath endswith "\\tcpvcon64a.exe" or FolderPath endswith "\\tcpview64a.exe" or FolderPath endswith "\\vmmap64a.exe" or FolderPath endswith "\\whois64a.exe" or FolderPath endswith "\\Winobj64a.exe" or FolderPath endswith "\\ZoomIt64a.exe") or (FolderPath endswith "\\accesschk.exe" or FolderPath endswith "\\accesschk64.exe" or FolderPath endswith "\\AccessEnum.exe" or FolderPath endswith "\\ADExplorer.exe" or FolderPath endswith "\\ADExplorer64.exe" or FolderPath endswith "\\ADInsight.exe" or FolderPath endswith "\\ADInsight64.exe" or FolderPath endswith "\\adrestore.exe" or FolderPath endswith "\\adrestore64.exe" or FolderPath endswith "\\Autologon.exe" or FolderPath endswith "\\Autologon64.exe" or FolderPath endswith "\\Autoruns.exe" or FolderPath endswith "\\Autoruns64.exe" or FolderPath endswith "\\autorunsc.exe" or FolderPath endswith "\\autorunsc64.exe" or FolderPath endswith "\\Bginfo.exe" or FolderPath endswith "\\Bginfo64.exe" or FolderPath endswith "\\Cacheset.exe" or FolderPath endswith "\\Cacheset64.exe" or FolderPath endswith "\\Clockres.exe" or FolderPath endswith "\\Clockres64.exe" or FolderPath endswith "\\Contig.exe" or FolderPath endswith "\\Contig64.exe" or FolderPath endswith "\\Coreinfo.exe" or FolderPath endswith "\\Coreinfo64.exe" or FolderPath endswith "\\CPUSTRES.EXE" or FolderPath endswith "\\CPUSTRES64.EXE" or FolderPath endswith "\\ctrl2cap.exe" or FolderPath endswith "\\Dbgview.exe" or FolderPath endswith "\\dbgview64.exe" or FolderPath endswith "\\Desktops.exe" or FolderPath endswith "\\Desktops64.exe" or FolderPath endswith "\\disk2vhd.exe" or FolderPath endswith "\\disk2vhd64.exe" or FolderPath endswith "\\diskext.exe" or FolderPath endswith "\\diskext64.exe" or FolderPath endswith "\\Diskmon.exe" or FolderPath endswith "\\Diskmon64.exe" or FolderPath endswith "\\DiskView.exe" or FolderPath endswith "\\DiskView64.exe" or FolderPath endswith "\\du.exe" or FolderPath endswith "\\du64.exe" or FolderPath endswith "\\efsdump.exe" or FolderPath endswith "\\FindLinks.exe" or FolderPath endswith "\\FindLinks64.exe" or FolderPath endswith "\\handle.exe" or FolderPath endswith "\\handle64.exe" or FolderPath endswith "\\hex2dec.exe" or FolderPath endswith "\\hex2dec64.exe" or FolderPath endswith "\\junction.exe" or FolderPath endswith "\\junction64.exe" or FolderPath endswith "\\ldmdump.exe" or FolderPath endswith "\\listdlls.exe" or FolderPath endswith "\\listdlls64.exe" or FolderPath endswith "\\livekd.exe" or FolderPath endswith "\\livekd64.exe" or FolderPath endswith "\\loadOrd.exe" or FolderPath endswith "\\loadOrd64.exe" or FolderPath endswith "\\loadOrdC.exe" or FolderPath endswith "\\loadOrdC64.exe" or FolderPath endswith "\\logonsessions.exe" or FolderPath endswith "\\logonsessions64.exe" or FolderPath endswith "\\movefile.exe" or FolderPath endswith "\\movefile64.exe" or FolderPath endswith "\\notmyfault.exe" or FolderPath endswith "\\notmyfault64.exe" or FolderPath endswith "\\notmyfaultc.exe" or FolderPath endswith "\\notmyfaultc64.exe" or FolderPath endswith "\\ntfsinfo.exe" or FolderPath endswith "\\ntfsinfo64.exe" or FolderPath endswith "\\pendmoves.exe" or FolderPath endswith "\\pendmoves64.exe" or FolderPath endswith "\\pipelist.exe" or FolderPath endswith "\\pipelist64.exe" or FolderPath endswith "\\portmon.exe" or FolderPath endswith "\\procdump.exe" or FolderPath endswith "\\procdump64.exe" or FolderPath endswith "\\procexp.exe" or FolderPath endswith "\\procexp64.exe" or FolderPath endswith "\\Procmon.exe" or FolderPath endswith "\\Procmon64.exe" or FolderPath endswith "\\psExec.exe" or FolderPath endswith "\\psExec64.exe" or FolderPath endswith "\\psfile.exe" or FolderPath endswith "\\psfile64.exe" or FolderPath endswith "\\psGetsid.exe" or FolderPath endswith "\\psGetsid64.exe" or FolderPath endswith "\\psInfo.exe" or FolderPath endswith "\\psInfo64.exe" or FolderPath endswith "\\pskill.exe" or FolderPath endswith "\\pskill64.exe" or FolderPath endswith "\\pslist.exe" or FolderPath endswith "\\pslist64.exe" or FolderPath endswith "\\psLoggedon.exe" or FolderPath endswith "\\psLoggedon64.exe" or FolderPath endswith "\\psloglist.exe" or FolderPath endswith "\\psloglist64.exe" or FolderPath endswith "\\pspasswd.exe" or FolderPath endswith "\\pspasswd64.exe" or FolderPath endswith "\\psping.exe" or FolderPath endswith "\\psping64.exe" or FolderPath endswith "\\psService.exe" or FolderPath endswith "\\psService64.exe" or FolderPath endswith "\\psshutdown.exe" or FolderPath endswith "\\psshutdown64.exe" or FolderPath endswith "\\pssuspend.exe" or FolderPath endswith "\\pssuspend64.exe" or FolderPath endswith "\\RAMMap.exe" or FolderPath endswith "\\RAMMap64.exe" or FolderPath endswith "\\RDCMan.exe" or FolderPath endswith "\\RegDelNull.exe" or FolderPath endswith "\\RegDelNull64.exe" or FolderPath endswith "\\regjump.exe" or FolderPath endswith "\\ru.exe" or FolderPath endswith "\\ru64.exe" or FolderPath endswith "\\sdelete.exe" or FolderPath endswith "\\sdelete64.exe" or FolderPath endswith "\\ShareEnum.exe" or FolderPath endswith "\\ShareEnum64.exe" or FolderPath endswith "\\shellRunas.exe" or FolderPath endswith "\\sigcheck.exe" or FolderPath endswith "\\sigcheck64.exe" or FolderPath endswith "\\streams.exe" or FolderPath endswith "\\streams64.exe" or FolderPath endswith "\\strings.exe" or FolderPath endswith "\\strings64.exe" or FolderPath endswith "\\sync.exe" or FolderPath endswith "\\sync64.exe" or FolderPath endswith "\\Sysmon.exe" or FolderPath endswith "\\Sysmon64.exe" or FolderPath endswith "\\tcpvcon.exe" or FolderPath endswith "\\tcpvcon64.exe" or FolderPath endswith "\\tcpview.exe" or FolderPath endswith "\\tcpview64.exe" or FolderPath endswith "\\Testlimit.exe" or FolderPath endswith "\\Testlimit64.exe" or FolderPath endswith "\\vmmap.exe" or FolderPath endswith "\\vmmap64.exe" or FolderPath endswith "\\Volumeid.exe" or FolderPath endswith "\\Volumeid64.exe" or FolderPath endswith "\\whois.exe" or FolderPath endswith "\\whois64.exe" or FolderPath endswith "\\Winobj.exe" or FolderPath endswith "\\Winobj64.exe" or FolderPath endswith "\\ZoomIt.exe" or FolderPath endswith "\\ZoomIt64.exe")) and (not(((isnull(ProcessVersionInfoCompanyName) or isnull(ProcessVersionInfoProductName)) or ((ProcessVersionInfoCompanyName in~ ("Sysinternals - www.sysinternals.com", "Sysinternals")) or ProcessVersionInfoProductName startswith "Sysinternals"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1218", "T1202", "T1036"]
  enabled                    = true

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = false
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
      by_entities             = []
      by_alert_details        = []
      by_custom_details       = []
    }
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}