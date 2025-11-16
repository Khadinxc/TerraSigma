resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_winpeas_execution" {
  name                       = "hacktool_winpeas_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - winPEAS Execution"
  description                = "WinPEAS is a script that search for possible paths to escalate privileges on Windows hosts. The checks are explained on book.hacktricks.xyz - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "https://github.com/carlospolop/PEASS-ng/releases/latest/download/" or (ProcessCommandLine contains " applicationsinfo" or ProcessCommandLine contains " browserinfo" or ProcessCommandLine contains " eventsinfo" or ProcessCommandLine contains " fileanalysis" or ProcessCommandLine contains " filesinfo" or ProcessCommandLine contains " processinfo" or ProcessCommandLine contains " servicesinfo" or ProcessCommandLine contains " windowscreds") or (InitiatingProcessCommandLine endswith " -linpeas" or ProcessCommandLine endswith " -linpeas") or (ProcessVersionInfoOriginalFileName =~ "winPEAS.exe" or (FolderPath endswith "\\winPEASany_ofs.exe" or FolderPath endswith "\\winPEASany.exe" or FolderPath endswith "\\winPEASx64_ofs.exe" or FolderPath endswith "\\winPEASx64.exe" or FolderPath endswith "\\winPEASx86_ofs.exe" or FolderPath endswith "\\winPEASx86.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Discovery"]
  techniques                 = ["T1082", "T1087", "T1046"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}