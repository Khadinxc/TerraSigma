resource "azurerm_sentinel_alert_rule_scheduled" "iis_webserver_log_deletion_via_commandline_utilities" {
  name                       = "iis_webserver_log_deletion_via_commandline_utilities"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "IIS WebServer Log Deletion via CommandLine Utilities"
  description                = "Detects attempts to delete Internet Information Services (IIS) log files via command line utilities, which is a common defense evasion technique used by attackers to cover their tracks. Threat actors often abuse vulnerabilities in web applications hosted on IIS servers to gain initial access and later delete IIS logs to evade detection. - Deletion of IIS logs that are older than a certain retention period as part of regular maintenance activities. - Legitimate schedule tasks or scripts that clean up log files regularly."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "del " or ProcessCommandLine contains "erase " or ProcessCommandLine contains "rm " or ProcessCommandLine contains "remove-item " or ProcessCommandLine contains "rmdir ") and ProcessCommandLine contains "\\inetpub\\logs\\" and ((FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("cmd.exe", "powershell.exe", "powershell_ise.exe", "pwsh.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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