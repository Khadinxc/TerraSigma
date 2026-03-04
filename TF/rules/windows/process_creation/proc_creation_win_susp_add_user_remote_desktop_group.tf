resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_susp_add_user_remote_desktop_group" {
  name                       = "proc_creation_win_susp_add_user_remote_desktop_group"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "User Added to Remote Desktop Users Group"
  description                = "Detects addition of users to the local Remote Desktop Users group via \"Net\" or \"Add-LocalGroupMember\". Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_add_user_remote_desktop_group.yml - Administrative activity | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_add_user_remote_desktop_group.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Remote Desktop Users" or ProcessCommandLine contains "Utilisateurs du Bureau à distance" or ProcessCommandLine contains "Usuarios de escritorio remoto") and ((ProcessCommandLine contains "localgroup " and ProcessCommandLine contains " /add") or (ProcessCommandLine contains "Add-LocalGroupMember " and ProcessCommandLine contains " -Group "))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Persistence", "LateralMovement"]
  techniques                 = ["T1133", "T1136", "T1021"]
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
}