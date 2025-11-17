resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_razerinstaller_explorer_subprocess" {
  name                       = "suspicious_razerinstaller_explorer_subprocess"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious RazerInstaller Explorer Subprocess"
  description                = "Detects a explorer.exe sub process of the RazerInstaller software which can be invoked from the installer to select a different installation folder but can also be exploited to escalate privileges to LOCAL SYSTEM - User selecting a different installation folder (check for other sub processes of this explorer.exe process)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessIntegrityLevel in~ ("System", "S-1-16-16384")) and InitiatingProcessFolderPath endswith "\\RazerInstaller.exe") and (not(FolderPath startswith "C:\\Windows\\Installer\\Razer\\Installer\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1553"]
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