resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_office_svchost_parent" {
  name                       = "proc_creation_win_office_svchost_parent"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious New Instance Of An Office COM Object"
  description                = "Detects an svchost process spawning an instance of an office application. This happens when the initial word application creates an instance of one of the Office COM objects such as 'Word.Application', 'Excel.Application', etc. This can be used by malicious actors to create malicious Office documents with macros on the fly. (See vba2clr project in the references) Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/process_creation/proc_creation_win_office_svchost_parent.yml - Legitimate usage of office automation via scripting | Source: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/process_creation/proc_creation_win_office_svchost_parent.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\eqnedt32.exe" or FolderPath endswith "\\excel.exe" or FolderPath endswith "\\msaccess.exe" or FolderPath endswith "\\mspub.exe" or FolderPath endswith "\\powerpnt.exe" or FolderPath endswith "\\visio.exe" or FolderPath endswith "\\winword.exe") and InitiatingProcessFolderPath endswith "\\svchost.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}