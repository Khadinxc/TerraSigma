resource "azurerm_sentinel_alert_rule_scheduled" "security_tools_keyword_lookup_via_findstr_exe" {
  name                       = "security_tools_keyword_lookup_via_findstr_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Security Tools Keyword Lookup Via Findstr.EXE"
  description                = "Detects execution of \"findstr\" to search for common names of security tools. Attackers often pipe the results of recon commands such as \"tasklist\" or \"whoami\" to \"findstr\" in order to filter out the results. This detection focuses on the keywords that the attacker might use as a filter."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine endswith " avira" or ProcessCommandLine endswith " avira\"" or ProcessCommandLine endswith " cb" or ProcessCommandLine endswith " cb\"" or ProcessCommandLine endswith " cylance" or ProcessCommandLine endswith " cylance\"" or ProcessCommandLine endswith " defender" or ProcessCommandLine endswith " defender\"" or ProcessCommandLine endswith " kaspersky" or ProcessCommandLine endswith " kaspersky\"" or ProcessCommandLine endswith " kes" or ProcessCommandLine endswith " kes\"" or ProcessCommandLine endswith " mc" or ProcessCommandLine endswith " mc\"" or ProcessCommandLine endswith " sec" or ProcessCommandLine endswith " sec\"" or ProcessCommandLine endswith " sentinel" or ProcessCommandLine endswith " sentinel\"" or ProcessCommandLine endswith " symantec" or ProcessCommandLine endswith " symantec\"" or ProcessCommandLine endswith " virus" or ProcessCommandLine endswith " virus\"") and ((FolderPath endswith "\\find.exe" or FolderPath endswith "\\findstr.exe") or (ProcessVersionInfoOriginalFileName in~ ("FIND.EXE", "FINDSTR.EXE")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1518"]
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