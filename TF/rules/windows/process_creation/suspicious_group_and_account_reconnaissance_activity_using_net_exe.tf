resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_group_and_account_reconnaissance_activity_using_net_exe" {
  name                       = "suspicious_group_and_account_reconnaissance_activity_using_net_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Group And Account Reconnaissance Activity Using Net.EXE"
  description                = "Detects suspicious reconnaissance command line activity on Windows systems using Net.EXE Check if the user that executed the commands is suspicious (e.g. service accounts, LOCAL_SYSTEM) - Inventory tool runs - Administrative activity"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe") or (ProcessVersionInfoOriginalFileName in~ ("net.exe", "net1.exe"))) and ((((ProcessCommandLine contains "domain admins" or ProcessCommandLine contains " administrator" or ProcessCommandLine contains " administrateur" or ProcessCommandLine contains "enterprise admins" or ProcessCommandLine contains "Exchange Trusted Subsystem" or ProcessCommandLine contains "Remote Desktop Users" or ProcessCommandLine contains "Utilisateurs du Bureau à distance" or ProcessCommandLine contains "Usuarios de escritorio remoto" or ProcessCommandLine contains " /do") and (ProcessCommandLine contains " group " or ProcessCommandLine contains " localgroup ")) and (not(ProcessCommandLine contains " /add"))) or (ProcessCommandLine contains " /do" and ProcessCommandLine contains " accounts "))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1087"]
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