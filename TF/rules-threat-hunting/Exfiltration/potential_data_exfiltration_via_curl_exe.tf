resource "azurerm_sentinel_alert_rule_scheduled" "potential_data_exfiltration_via_curl_exe" {
  name                       = "potential_data_exfiltration_via_curl_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Data Exfiltration Via Curl.EXE"
  description                = "Detects the execution of the \"curl\" process with \"upload\" flags. Which might indicate potential data exfiltration - Scripts created by developers and admins"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains " --form" or ProcessCommandLine contains " --upload-file " or ProcessCommandLine contains " --data " or ProcessCommandLine contains " --data-") or ProcessCommandLine matches regex "\\s-[FTd]\\s") and (FolderPath endswith "\\curl.exe" or ProcessVersionInfoProductName =~ "The curl executable")) and (not((ProcessCommandLine contains "://localhost" or ProcessCommandLine contains "://127.0.0.1")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration", "CommandAndControl"]
  techniques                 = ["T1567", "T1105"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}