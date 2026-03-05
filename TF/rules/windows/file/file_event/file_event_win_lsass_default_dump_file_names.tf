resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_lsass_default_dump_file_names" {
  name                       = "file_event_win_lsass_default_dump_file_names"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "LSASS Process Memory Dump Files"
  description                = <<DESC
    Detects creation of files with names used by different memory dumping tools to create a memory dump of the LSASS process memory, which contains user credentials.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_lsass_default_dump_file_names.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith "\\Andrew.dmp" or FolderPath endswith "\\Coredump.dmp" or FolderPath endswith "\\lsass.dmp" or FolderPath endswith "\\lsass.rar" or FolderPath endswith "\\lsass.zip" or FolderPath endswith "\\NotLSASS.zip" or FolderPath endswith "\\PPLBlade.dmp" or FolderPath endswith "\\rustive.dmp") or (FolderPath contains "\\lsass_2" or FolderPath contains "\\lsassdmp" or FolderPath contains "\\lsassdump") or (FolderPath contains "\\lsass" and FolderPath contains ".dmp") or (FolderPath contains "SQLDmpr" and FolderPath endswith ".mdmp") or ((FolderPath contains "\\nanodump" or FolderPath contains "\\proc_") and FolderPath endswith ".dmp")
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}