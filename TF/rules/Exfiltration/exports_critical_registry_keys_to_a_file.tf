resource "azurerm_sentinel_alert_rule_scheduled" "exports_critical_registry_keys_to_a_file" {
  name                       = "exports_critical_registry_keys_to_a_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Exports Critical Registry Keys To a File"
  description                = "Detects the export of a crital Registry key to a file. - Dumping hives for legitimate purpouse i.e. backup or forensic investigation"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -E " or ProcessCommandLine contains " /E " or ProcessCommandLine contains " –E " or ProcessCommandLine contains " —E " or ProcessCommandLine contains " ―E ") and (ProcessCommandLine contains "hklm" or ProcessCommandLine contains "hkey_local_machine") and (ProcessCommandLine endswith "\\system" or ProcessCommandLine endswith "\\sam" or ProcessCommandLine endswith "\\security") and (FolderPath endswith "\\regedit.exe" or ProcessVersionInfoOriginalFileName =~ "REGEDIT.EXE")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration", "Discovery"]
  techniques                 = ["T1012"]
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