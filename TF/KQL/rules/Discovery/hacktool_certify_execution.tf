resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_certify_execution" {
  name                       = "hacktool_certify_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Certify Execution"
  description                = "Detects Certify a tool for Active Directory certificate abuse based on PE metadata characteristics and common command line arguments."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\Certify.exe" or ProcessVersionInfoOriginalFileName =~ "Certify.exe" or ProcessVersionInfoFileDescription contains "Certify") or ((ProcessCommandLine contains ".exe cas " or ProcessCommandLine contains ".exe find " or ProcessCommandLine contains ".exe pkiobjects " or ProcessCommandLine contains ".exe request " or ProcessCommandLine contains ".exe download ") and (ProcessCommandLine contains " /vulnerable" or ProcessCommandLine contains " /template:" or ProcessCommandLine contains " /altname:" or ProcessCommandLine contains " /domain:" or ProcessCommandLine contains " /path:" or ProcessCommandLine contains " /ca:"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery", "CredentialAccess"]
  techniques                 = ["T1649"]
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