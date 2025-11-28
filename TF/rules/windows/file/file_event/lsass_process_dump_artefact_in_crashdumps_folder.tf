resource "azurerm_sentinel_alert_rule_scheduled" "lsass_process_dump_artefact_in_crashdumps_folder" {
  name                       = "lsass_process_dump_artefact_in_crashdumps_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "LSASS Process Dump Artefact In CrashDumps Folder"
  description                = "Detects the presence of an LSASS dump file in the \"CrashDumps\" folder. This could be a sign of LSASS credential dumping. Techniques such as the LSASS Shtinkering have been seen abusing the Windows Error Reporting to dump said process. - Rare legitimate dump of the process by the operating system due to a crash of lsass"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath contains "lsass.exe." and FolderPath endswith ".dmp" and FolderPath startswith "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\CrashDumps\\"
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}