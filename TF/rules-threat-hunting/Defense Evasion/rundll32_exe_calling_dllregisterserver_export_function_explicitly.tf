resource "azurerm_sentinel_alert_rule_scheduled" "rundll32_exe_calling_dllregisterserver_export_function_explicitly" {
  name                       = "rundll32_exe_calling_dllregisterserver_export_function_explicitly"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Rundll32.EXE Calling DllRegisterServer Export Function Explicitly"
  description                = "Detects when the DLL export function 'DllRegisterServer' is called in the commandline by Rundll32 explicitly where the DLL is located in a non-standard path. - Legitimate usage as part of application installation, but less likely from e.g. temporary paths. - Not every instance is considered malicious, but this rule will capture the malicious usages."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "DllRegisterServer" and (FolderPath endswith "\\rundll32.exe" or ProcessVersionInfoOriginalFileName =~ "RUNDLL32.EXE")) and (not((ProcessCommandLine contains ":\\Program Files (x86)" or ProcessCommandLine contains ":\\Program Files\\" or ProcessCommandLine contains ":\\Windows\\System32\\" or ProcessCommandLine contains ":\\Windows\\SysWOW64\\")))
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