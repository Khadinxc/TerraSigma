resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_system_user_process_creation" {
  name                       = "suspicious_system_user_process_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious SYSTEM User Process Creation"
  description                = "Detects a suspicious process creation as SYSTEM user (suspicious program or command line parameter) - Administrative activity - Scripts and administrative tools used in the monitored environment - Monitoring activity"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessIntegrityLevel in~ ("System", "S-1-16-16384")) and (AccountName contains "AUTHORI" or AccountName contains "AUTORI")) and ((FolderPath endswith "\\calc.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\forfiles.exe" or FolderPath endswith "\\hh.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\ping.exe" or FolderPath endswith "\\wscript.exe") or ProcessCommandLine matches regex "net\\s+user\\s+" or (ProcessCommandLine contains " -NoP " or ProcessCommandLine contains " -W Hidden " or ProcessCommandLine contains " -decode " or ProcessCommandLine contains " /decode " or ProcessCommandLine contains " /urlcache " or ProcessCommandLine contains " -urlcache " or (ProcessCommandLine contains " -e" and ProcessCommandLine contains " JAB") or (ProcessCommandLine contains " -e" and ProcessCommandLine contains " SUVYI") or (ProcessCommandLine contains " -e" and ProcessCommandLine contains " SQBFAFgA") or (ProcessCommandLine contains " -e" and ProcessCommandLine contains " aWV4I") or (ProcessCommandLine contains " -e" and ProcessCommandLine contains " IAB") or (ProcessCommandLine contains " -e" and ProcessCommandLine contains " PAA") or (ProcessCommandLine contains " -e" and ProcessCommandLine contains " aQBlAHgA") or ProcessCommandLine contains "vssadmin delete shadows" or ProcessCommandLine contains "reg SAVE HKLM" or ProcessCommandLine contains " -ma " or ProcessCommandLine contains "Microsoft\\Windows\\CurrentVersion\\Run" or ProcessCommandLine contains ".downloadstring(" or ProcessCommandLine contains ".downloadfile(" or ProcessCommandLine contains " /ticket:" or ProcessCommandLine contains "dpapi::" or ProcessCommandLine contains "event::clear" or ProcessCommandLine contains "event::drop" or ProcessCommandLine contains "id::modify" or ProcessCommandLine contains "kerberos::" or ProcessCommandLine contains "lsadump::" or ProcessCommandLine contains "misc::" or ProcessCommandLine contains "privilege::" or ProcessCommandLine contains "rpc::" or ProcessCommandLine contains "sekurlsa::" or ProcessCommandLine contains "sid::" or ProcessCommandLine contains "token::" or ProcessCommandLine contains "vault::cred" or ProcessCommandLine contains "vault::list" or ProcessCommandLine contains " p::d " or ProcessCommandLine contains ";iex(" or ProcessCommandLine contains "MiniDump"))) and (not((InitiatingProcessFolderPath contains ":\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\" or (ProcessCommandLine contains " -ma " and (FolderPath contains ":\\Program Files (x86)\\Java\\" or FolderPath contains ":\\Program Files\\Java\\") and FolderPath endswith "\\bin\\jp2launcher.exe" and (InitiatingProcessFolderPath contains ":\\Program Files (x86)\\Java\\" or InitiatingProcessFolderPath contains ":\\Program Files\\Java\\") and InitiatingProcessFolderPath endswith "\\bin\\javaws.exe") or (ProcessCommandLine contains "ping" and ProcessCommandLine contains "127.0.0.1" and ProcessCommandLine contains " -n ") or (FolderPath endswith "\\PING.EXE" and InitiatingProcessCommandLine contains "\\DismFoDInstall.cmd"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1134", "T1003", "T1027"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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