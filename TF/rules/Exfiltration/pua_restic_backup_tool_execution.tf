resource "azurerm_sentinel_alert_rule_scheduled" "pua_restic_backup_tool_execution" {
  name                       = "pua_restic_backup_tool_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Restic Backup Tool Execution"
  description                = "Detects the execution of the Restic backup tool, which can be used for data exfiltration. Threat actors may leverage Restic to back up and exfiltrate sensitive data to remote storage locations, including cloud services. If not legitimately used in the enterprise environment, its presence may indicate malicious activity. - Legitimate use of Restic for backup purposes within the organization."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "sftp:" or ProcessCommandLine contains "rest:http" or ProcessCommandLine contains "s3:s3." or ProcessCommandLine contains "s3.http" or ProcessCommandLine contains "azure:" or ProcessCommandLine contains " gs:" or ProcessCommandLine contains "rclone:" or ProcessCommandLine contains "swift:" or ProcessCommandLine contains " b2:") and (ProcessCommandLine contains " init " and ProcessCommandLine contains " -r ")) or ((ProcessCommandLine contains "--password-file" and ProcessCommandLine contains "init" and ProcessCommandLine contains " -r ") or (ProcessCommandLine contains "--use-fs-snapshot" and ProcessCommandLine contains "backup" and ProcessCommandLine contains " -r "))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration"]
  techniques                 = ["T1048", "T1567"]
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
}