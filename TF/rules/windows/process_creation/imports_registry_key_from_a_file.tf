resource "azurerm_sentinel_alert_rule_scheduled" "imports_registry_key_from_a_file" {
  name                       = "imports_registry_key_from_a_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Imports Registry Key From a File"
  description                = "Detects the import of the specified file to the registry with regedit.exe. - Legitimate import of keys - Evernote"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " /i " or ProcessCommandLine contains " /s " or ProcessCommandLine contains ".reg") and (FolderPath endswith "\\regedit.exe" or ProcessVersionInfoOriginalFileName =~ "REGEDIT.EXE")) and (not(((ProcessCommandLine contains " -e " or ProcessCommandLine contains " /e " or ProcessCommandLine contains " –e " or ProcessCommandLine contains " —e " or ProcessCommandLine contains " ―e " or ProcessCommandLine contains " -a " or ProcessCommandLine contains " /a " or ProcessCommandLine contains " –a " or ProcessCommandLine contains " —a " or ProcessCommandLine contains " ―a " or ProcessCommandLine contains " -c " or ProcessCommandLine contains " /c " or ProcessCommandLine contains " –c " or ProcessCommandLine contains " —c " or ProcessCommandLine contains " ―c ") and ProcessCommandLine matches regex ":[^ \\\\]")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112"]
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