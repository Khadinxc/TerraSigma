resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_stracciatella_execution" {
  name                       = "hacktool_stracciatella_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Stracciatella Execution"
  description                = "Detects Stracciatella which executes a Powershell runspace from within C# (aka SharpPick technique) with AMSI, ETW and Script Block Logging disabled based on PE metadata characteristics. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\Stracciatella.exe" or ProcessVersionInfoOriginalFileName =~ "Stracciatella.exe" or ProcessVersionInfoFileDescription =~ "Stracciatella" or (SHA256 startswith "9d25e61ec1527e2a69d7c2a4e3fe2fe15890710c198a66a9f25d99fdf6c7b956" or SHA256 startswith "fd16609bd9830c63b9413671678bb159b89c357d21942ddbb6b93add808d121a")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1059", "T1562"]
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
    field_mapping {
      identifier  = "SHA256"
      column_name = "SHA256"
    }
  }
}