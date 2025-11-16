resource "azurerm_sentinel_alert_rule_scheduled" "potential_password_spraying_attempt_using_dsacls_exe" {
  name                       = "potential_password_spraying_attempt_using_dsacls_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Password Spraying Attempt Using Dsacls.EXE"
  description                = "Detects possible password spraying attempts using Dsacls - Legitimate use of dsacls to bind to an LDAP session"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/user:" and ProcessCommandLine contains "/passwd:") and (FolderPath endswith "\\dsacls.exe" or ProcessVersionInfoOriginalFileName =~ "DSACLS.EXE")
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