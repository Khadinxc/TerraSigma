resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_manipulation_of_default_accounts_via_net_exe" {
  name                       = "suspicious_manipulation_of_default_accounts_via_net_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Manipulation Of Default Accounts Via Net.EXE"
  description                = "Detects suspicious manipulations of default accounts such as 'administrator' and 'guest'. For example 'enable' or 'disable' accounts or change the password...etc - Some false positives could occur with the admin or guest account. It depends on the scripts being used by the admins in your env. If you experience a lot of FP you could reduce the level to medium"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe") or (ProcessVersionInfoOriginalFileName in~ ("net.exe", "net1.exe"))) and ProcessCommandLine contains " user " and (ProcessCommandLine contains " Järjestelmänvalvoja " or ProcessCommandLine contains " Rendszergazda " or ProcessCommandLine contains " Администратор " or ProcessCommandLine contains " Administrateur " or ProcessCommandLine contains " Administrador " or ProcessCommandLine contains " Administratör " or ProcessCommandLine contains " Administrator " or ProcessCommandLine contains " guest " or ProcessCommandLine contains " DefaultAccount " or ProcessCommandLine contains " \"Järjestelmänvalvoja\" " or ProcessCommandLine contains " \"Rendszergazda\" " or ProcessCommandLine contains " \"Администратор\" " or ProcessCommandLine contains " \"Administrateur\" " or ProcessCommandLine contains " \"Administrador\" " or ProcessCommandLine contains " \"Administratör\" " or ProcessCommandLine contains " \"Administrator\" " or ProcessCommandLine contains " \"guest\" " or ProcessCommandLine contains " \"DefaultAccount\" " or ProcessCommandLine contains " 'Järjestelmänvalvoja' " or ProcessCommandLine contains " 'Rendszergazda' " or ProcessCommandLine contains " 'Администратор' " or ProcessCommandLine contains " 'Administrateur' " or ProcessCommandLine contains " 'Administrador' " or ProcessCommandLine contains " 'Administratör' " or ProcessCommandLine contains " 'Administrator' " or ProcessCommandLine contains " 'guest' " or ProcessCommandLine contains " 'DefaultAccount' ")) and (not((ProcessCommandLine contains "guest" and ProcessCommandLine contains "/active no")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1560"]
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