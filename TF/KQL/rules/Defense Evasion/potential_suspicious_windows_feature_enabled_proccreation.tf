resource "azurerm_sentinel_alert_rule_scheduled" "potential_suspicious_windows_feature_enabled_proccreation" {
  name                       = "potential_suspicious_windows_feature_enabled_proccreation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Suspicious Windows Feature Enabled - ProcCreation"
  description                = "Detects usage of the built-in PowerShell cmdlet \"Enable-WindowsOptionalFeature\" used as a Deployment Image Servicing and Management tool. Similar to DISM.exe, this cmdlet is used to enumerate, install, uninstall, configure, and update features and packages in Windows images - Legitimate usage of the features listed in the rule."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Enable-WindowsOptionalFeature" and ProcessCommandLine contains "-Online" and ProcessCommandLine contains "-FeatureName") and (ProcessCommandLine contains "TelnetServer" or ProcessCommandLine contains "Internet-Explorer-Optional-amd64" or ProcessCommandLine contains "TFTP" or ProcessCommandLine contains "SMB1Protocol" or ProcessCommandLine contains "Client-ProjFS" or ProcessCommandLine contains "Microsoft-Windows-Subsystem-Linux")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
  }
}