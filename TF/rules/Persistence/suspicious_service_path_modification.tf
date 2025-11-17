resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_service_path_modification" {
  name                       = "suspicious_service_path_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Service Path Modification"
  description                = "Detects service path modification via the \"sc\" binary to a suspicious command or path - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "powershell" or ProcessCommandLine contains "cmd " or ProcessCommandLine contains "mshta" or ProcessCommandLine contains "wscript" or ProcessCommandLine contains "cscript" or ProcessCommandLine contains "rundll32" or ProcessCommandLine contains "svchost" or ProcessCommandLine contains "dllhost" or ProcessCommandLine contains "cmd.exe /c" or ProcessCommandLine contains "cmd.exe /k" or ProcessCommandLine contains "cmd.exe /r" or ProcessCommandLine contains "cmd /c" or ProcessCommandLine contains "cmd /k" or ProcessCommandLine contains "cmd /r" or ProcessCommandLine contains "C:\\Users\\Public" or ProcessCommandLine contains "\\Downloads\\" or ProcessCommandLine contains "\\Desktop\\" or ProcessCommandLine contains "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" or ProcessCommandLine contains "C:\\Windows\\TEMP\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp") and (ProcessCommandLine contains "config" and ProcessCommandLine contains "binPath") and FolderPath endswith "\\sc.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1543"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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