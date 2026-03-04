resource "azurerm_sentinel_alert_rule_scheduled" "file_event_lnx_susp_shell_script_under_profile_directory" {
  name                       = "file_event_lnx_susp_shell_script_under_profile_directory"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Shell Script Creation in Profile Folder"
  description                = "Detects the creation of shell scripts under the \"profile.d\" path. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/file_event/file_event_lnx_susp_shell_script_under_profile_directory.yml - Legitimate shell scripts in the \"profile.d\" directory could be common in your environment. Apply additional filter accordingly via \"image\", by adding specific filenames you \"trust\" or by correlating it with other events. - Regular file creation during system update or software installation by the package manager | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/file_event/file_event_lnx_susp_shell_script_under_profile_directory.yml"
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath contains "/etc/profile.d/" and (FolderPath endswith ".csh" or FolderPath endswith ".sh")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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