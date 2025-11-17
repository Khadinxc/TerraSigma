resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_processes_spawned_by_winrm" {
  name                       = "suspicious_processes_spawned_by_winrm"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Processes Spawned by WinRM"
  description                = "Detects suspicious processes including shells spawnd from WinRM host process - Legitimate WinRM usage"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\sh.exe" or FolderPath endswith "\\bash.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\wsl.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\whoami.exe" or FolderPath endswith "\\bitsadmin.exe") and InitiatingProcessFolderPath endswith "\\wsmprovhost.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1190"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}