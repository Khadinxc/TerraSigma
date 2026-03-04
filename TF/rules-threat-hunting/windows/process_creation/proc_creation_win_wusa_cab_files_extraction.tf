resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_wusa_cab_files_extraction" {
  name                       = "proc_creation_win_wusa_cab_files_extraction"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Cab File Extraction Via Wusa.EXE"
  description                = "Detects execution of the \"wusa.exe\" (Windows Update Standalone Installer) utility to extract cab using the \"/extract\" argument that is no longer supported. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/process_creation/proc_creation_win_wusa_cab_files_extraction.yml - The \"extract\" flag still works on older 'wusa.exe' versions, which could be a legitimate use (monitor the path of the cab being extracted) | Source: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/process_creation/proc_creation_win_wusa_cab_files_extraction.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "/extract:" and FolderPath endswith "\\wusa.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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