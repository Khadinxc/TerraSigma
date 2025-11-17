resource "azurerm_sentinel_alert_rule_scheduled" "local_accounts_discovery" {
  name                       = "local_accounts_discovery"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Local Accounts Discovery"
  description                = "Local accounts, System Owner/User discovery using operating systems utilities - Legitimate administrator or user enumerates local users for legitimate reason"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains " /c" and ProcessCommandLine contains "dir " and ProcessCommandLine contains "\\Users\\") and FolderPath endswith "\\cmd.exe") and (not(ProcessCommandLine contains " rmdir "))) or ((ProcessCommandLine contains "user" and (FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe")) and (not((ProcessCommandLine contains "/domain" or ProcessCommandLine contains "/add" or ProcessCommandLine contains "/delete" or ProcessCommandLine contains "/active" or ProcessCommandLine contains "/expires" or ProcessCommandLine contains "/passwordreq" or ProcessCommandLine contains "/scriptpath" or ProcessCommandLine contains "/times" or ProcessCommandLine contains "/workstations")))) or ((ProcessCommandLine contains " /l" and FolderPath endswith "\\cmdkey.exe") or ((FolderPath endswith "\\whoami.exe" or FolderPath endswith "\\quser.exe" or FolderPath endswith "\\qwinsta.exe") or (ProcessVersionInfoOriginalFileName in~ ("whoami.exe", "quser.exe", "qwinsta.exe"))) or ((ProcessCommandLine contains "useraccount" and ProcessCommandLine contains "get") and FolderPath endswith "\\wmic.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1033", "T1087"]
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