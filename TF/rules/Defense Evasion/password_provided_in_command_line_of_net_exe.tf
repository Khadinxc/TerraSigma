resource "azurerm_sentinel_alert_rule_scheduled" "password_provided_in_command_line_of_net_exe" {
  name                       = "password_provided_in_command_line_of_net_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Password Provided In Command Line Of Net.EXE"
  description                = "Detects a when net.exe is called with a password in the command line"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " use " and (ProcessCommandLine contains ":" and ProcessCommandLine contains "\\") and (ProcessCommandLine contains "/USER:" and ProcessCommandLine contains " ")) and ((FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe") or (ProcessVersionInfoOriginalFileName in~ ("net.exe", "net1.exe")))) and (not(ProcessCommandLine endswith " "))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "InitialAccess", "Persistence", "PrivilegeEscalation", "LateralMovement"]
  techniques                 = ["T1021", "T1078"]
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
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
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