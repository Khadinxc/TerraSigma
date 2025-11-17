resource "azurerm_sentinel_alert_rule_scheduled" "dumping_of_sensitive_hives_via_reg_exe" {
  name                       = "dumping_of_sensitive_hives_via_reg_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Dumping of Sensitive Hives Via Reg.EXE"
  description                = "Detects the usage of \"reg.exe\" in order to dump sensitive registry hives. This includes SAM, SYSTEM and SECURITY hives. - Dumping hives for legitimate purpouse i.e. backup or forensic investigation"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " save " or ProcessCommandLine contains " export " or ProcessCommandLine contains " ˢave " or ProcessCommandLine contains " eˣport ") and (ProcessCommandLine contains "\\system" or ProcessCommandLine contains "\\sam" or ProcessCommandLine contains "\\security" or ProcessCommandLine contains "\\ˢystem" or ProcessCommandLine contains "\\syˢtem" or ProcessCommandLine contains "\\ˢyˢtem" or ProcessCommandLine contains "\\ˢam" or ProcessCommandLine contains "\\ˢecurity") and (ProcessCommandLine contains "hklm" or ProcessCommandLine contains "hk˪m" or ProcessCommandLine contains "hkey_local_machine" or ProcessCommandLine contains "hkey_˪ocal_machine" or ProcessCommandLine contains "hkey_loca˪_machine" or ProcessCommandLine contains "hkey_˪oca˪_machine") and (FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe")
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