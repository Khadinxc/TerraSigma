resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_msiexec_embedding_parent" {
  name                       = "suspicious_msiexec_embedding_parent"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious MsiExec Embedding Parent"
  description                = "Adversaries may abuse msiexec.exe to proxy the execution of malicious payloads"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\cmd.exe") and (InitiatingProcessCommandLine contains "MsiExec.exe" and InitiatingProcessCommandLine contains "-Embedding ")) and (not(((ProcessCommandLine contains "C:\\Program Files\\SplunkUniversalForwarder\\bin\\" and FolderPath endswith ":\\Windows\\System32\\cmd.exe") or (ProcessCommandLine contains "\\DismFoDInstall.cmd" or (InitiatingProcessCommandLine contains "\\MsiExec.exe -Embedding " and InitiatingProcessCommandLine contains "Global\\MSI0000")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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