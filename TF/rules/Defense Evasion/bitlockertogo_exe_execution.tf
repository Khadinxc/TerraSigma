resource "azurerm_sentinel_alert_rule_scheduled" "bitlockertogo_exe_execution" {
  name                       = "bitlockertogo_exe_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "BitLockerTogo.EXE Execution"
  description                = "Detects the execution of \"BitLockerToGo.EXE\". BitLocker To Go is BitLocker Drive Encryption on removable data drives. This feature includes the encryption of, USB flash drives, SD cards, External hard disk drives, Other drives that are formatted by using the NTFS, FAT16, FAT32, or exFAT file system. This is a rarely used application and usage of it at all is worth investigating. Malware such as Lumma stealer has been seen using this process as a target for process hollowing. - Legitimate usage of BitLockerToGo.exe to encrypt portable devices."
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\BitLockerToGo.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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