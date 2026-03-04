resource "azurerm_sentinel_alert_rule_scheduled" "volumeshadowcopy_symlink_creation_via_mklink" {
  name                       = "volumeshadowcopy_symlink_creation_via_mklink"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "VolumeShadowCopy Symlink Creation Via Mklink"
  description                = "Shadow Copies storage symbolic link creation using operating systems utilities - Legitimate administrator working with shadow copies, access for backup purposes | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/volumeshadowcopy_symlink_creation_via_mklink.tf"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "mklink" and ProcessCommandLine contains "HarddiskVolumeShadowCopy"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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