resource "azurerm_sentinel_alert_rule_scheduled" "sensitive_file_recovery_from_backup_via_wbadmin_exe" {
  name                       = "sensitive_file_recovery_from_backup_via_wbadmin_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Sensitive File Recovery From Backup Via Wbadmin.EXE"
  description                = "Detects the dump of highly sensitive files such as \"NTDS.DIT\" and \"SECURITY\" hive. Attackers can leverage the \"wbadmin\" utility in order to dump sensitive files that might contain credential or sensitive information."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "\\config\\SAM" or ProcessCommandLine contains "\\config\\SECURITY" or ProcessCommandLine contains "\\config\\SYSTEM" or ProcessCommandLine contains "\\Windows\\NTDS\\NTDS.dit") and (ProcessCommandLine contains " recovery" and ProcessCommandLine contains "recoveryTarget" and ProcessCommandLine contains "itemtype:File")) and (FolderPath endswith "\\wbadmin.exe" or ProcessVersionInfoOriginalFileName =~ "WBADMIN.EXE")
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