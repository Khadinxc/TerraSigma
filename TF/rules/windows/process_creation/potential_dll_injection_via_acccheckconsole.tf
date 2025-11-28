resource "azurerm_sentinel_alert_rule_scheduled" "potential_dll_injection_via_acccheckconsole" {
  name                       = "potential_dll_injection_via_acccheckconsole"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential DLL Injection Via AccCheckConsole"
  description                = "Detects the execution \"AccCheckConsole\" a command-line tool for verifying the accessibility implementation of an application's UI. One of the tests that this checker can run are called \"verification routine\", which tests for things like Consistency, Navigation, etc. The tool allows a user to provide a DLL that can contain a custom \"verification routine\". An attacker can build such DLLs and pass it via the CLI, which would then be loaded in the context of the \"AccCheckConsole\" utility. - Legitimate use of the UI Accessibility Checker"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -hwnd" or ProcessCommandLine contains " -process " or ProcessCommandLine contains " -window ") and (FolderPath endswith "\\AccCheckConsole.exe" or ProcessVersionInfoOriginalFileName =~ "AccCheckConsole.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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