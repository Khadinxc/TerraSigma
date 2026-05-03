resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_hktl_netexec_file_indicators" {
  name                       = "file_event_win_hktl_netexec_file_indicators"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - NetExec File Indicators"
  description                = <<DESC
    Detects file creation events indicating NetExec (nxc.exe) execution on the local machine. NetExec is a PyInstaller-bundled binary that extracts its embedded data files to a "_MEI<random>" directory under the Temp folder upon execution. Files dropped under the "\nxc\" sub-directory of that extraction path are unique to NetExec and serve as reliable on-disk indicators of execution. NetExec (formerly CrackMapExec) is a widely used post-exploitation and lateral movement tool used for Active Directory enumeration, credential harvesting, and remote code execution.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_hktl_netexec_file_indicators.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath contains "\\nxc-windows-latest\\" or (FolderPath contains "\\Temp\\_MEI" and FolderPath contains "\\nxc\\data\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "LateralMovement", "Discovery"]
  techniques                 = ["T1021", "T1059"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}