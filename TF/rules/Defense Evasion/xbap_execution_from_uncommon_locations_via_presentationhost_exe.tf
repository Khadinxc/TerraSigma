resource "azurerm_sentinel_alert_rule_scheduled" "xbap_execution_from_uncommon_locations_via_presentationhost_exe" {
  name                       = "xbap_execution_from_uncommon_locations_via_presentationhost_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "XBAP Execution From Uncommon Locations Via PresentationHost.EXE"
  description                = "Detects the execution of \".xbap\" (Browser Applications) files via PresentationHost.EXE from an uncommon location. These files can be abused to run malicious \".xbap\" files any bypass AWL - Legitimate \".xbap\" being executed via \"PresentationHost\""
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".xbap" and (FolderPath endswith "\\presentationhost.exe" or ProcessVersionInfoOriginalFileName =~ "PresentationHost.exe")) and (not((ProcessCommandLine contains " C:\\Windows\\" or ProcessCommandLine contains " C:\\Program Files")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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