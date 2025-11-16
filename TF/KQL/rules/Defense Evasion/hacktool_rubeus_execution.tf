resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_rubeus_execution" {
  name                       = "hacktool_rubeus_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Rubeus Execution"
  description                = "Detects the execution of the hacktool Rubeus via PE information of command line parameters - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\Rubeus.exe" or ProcessVersionInfoOriginalFileName =~ "Rubeus.exe" or ProcessVersionInfoFileDescription =~ "Rubeus" or (ProcessCommandLine contains "asreproast " or ProcessCommandLine contains "dump /service:krbtgt " or ProcessCommandLine contains "dump /luid:0x" or ProcessCommandLine contains "kerberoast " or ProcessCommandLine contains "createnetonly /program:" or ProcessCommandLine contains "ptt /ticket:" or ProcessCommandLine contains "/impersonateuser:" or ProcessCommandLine contains "renew /ticket:" or ProcessCommandLine contains "asktgt /user:" or ProcessCommandLine contains "harvest /interval:" or ProcessCommandLine contains "s4u /user:" or ProcessCommandLine contains "s4u /ticket:" or ProcessCommandLine contains "hash /password:" or ProcessCommandLine contains "golden /aes256:" or ProcessCommandLine contains "silver /user:")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess", "LateralMovement"]
  techniques                 = ["T1003", "T1558", "T1550"]
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