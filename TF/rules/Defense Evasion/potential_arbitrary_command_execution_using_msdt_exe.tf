resource "azurerm_sentinel_alert_rule_scheduled" "potential_arbitrary_command_execution_using_msdt_exe" {
  name                       = "potential_arbitrary_command_execution_using_msdt_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Arbitrary Command Execution Using Msdt.EXE"
  description                = "Detects processes leveraging the \"ms-msdt\" handler or the \"msdt.exe\" binary to execute arbitrary commands as seen in the follina (CVE-2022-30190) vulnerability"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\msdt.exe" or ProcessVersionInfoOriginalFileName =~ "msdt.exe") and (ProcessCommandLine contains "IT_BrowseForFile=" or (ProcessCommandLine contains " PCWDiagnostic" and (ProcessCommandLine contains " -af " or ProcessCommandLine contains " /af " or ProcessCommandLine contains " –af " or ProcessCommandLine contains " —af " or ProcessCommandLine contains " ―af ")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1202"]
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