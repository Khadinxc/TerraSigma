resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_execution_of_powershell_with_base64" {
  name                       = "suspicious_execution_of_powershell_with_base64"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Execution of Powershell with Base64"
  description                = "Commandline to launch powershell with a base64 payload"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -e " or ProcessCommandLine contains " -en " or ProcessCommandLine contains " -enc " or ProcessCommandLine contains " -enco" or ProcessCommandLine contains " -ec ") and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe")) and (not(((InitiatingProcessFolderPath contains "C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\" or InitiatingProcessFolderPath contains "\\gc_worker.exe") or ProcessCommandLine contains " -Encoding ")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}