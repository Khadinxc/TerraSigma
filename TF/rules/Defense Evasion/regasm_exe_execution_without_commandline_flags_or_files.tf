resource "azurerm_sentinel_alert_rule_scheduled" "regasm_exe_execution_without_commandline_flags_or_files" {
  name                       = "regasm_exe_execution_without_commandline_flags_or_files"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "RegAsm.EXE Execution Without CommandLine Flags or Files"
  description                = "Detects the execution of \"RegAsm.exe\" without a commandline flag or file, which might indicate potential process injection activity. Usually \"RegAsm.exe\" should point to a dedicated DLL file or call the help with the \"/?\" flag. - Legitimate use of Regasm by developers."
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine endswith "RegAsm" or ProcessCommandLine endswith "RegAsm.exe" or ProcessCommandLine endswith "RegAsm.exe\"" or ProcessCommandLine endswith "RegAsm.exe'") and (FolderPath endswith "\\RegAsm.exe" or ProcessVersionInfoOriginalFileName =~ "RegAsm.exe")
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