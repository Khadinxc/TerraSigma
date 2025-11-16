resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_iis_url_globalrules_rewrite_via_appcmd" {
  name                       = "suspicious_iis_url_globalrules_rewrite_via_appcmd"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious IIS URL GlobalRules Rewrite Via AppCmd"
  description                = "Detects usage of \"appcmd\" to create new global URL rewrite rules. This behaviour has been observed being used by threat actors to add new rules so they can access their webshells. - Legitimate usage of appcmd to add new URL rewrite rules"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "set" and ProcessCommandLine contains "config" and ProcessCommandLine contains "section:system.webServer/rewrite/globalRules" and ProcessCommandLine contains "commit:") and (FolderPath endswith "\\appcmd.exe" or ProcessVersionInfoOriginalFileName =~ "appcmd.exe")
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