resource "azurerm_sentinel_alert_rule_scheduled" "arbitrary_dll_or_csproj_code_execution_via_dotnet_exe" {
  name                       = "arbitrary_dll_or_csproj_code_execution_via_dotnet_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE"
  description                = "Detects execution of arbitrary DLLs or unsigned code via a \".csproj\" files via Dotnet.EXE. - Legitimate administrator usage"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine endswith ".csproj" or ProcessCommandLine endswith ".csproj\"" or ProcessCommandLine endswith ".dll" or ProcessCommandLine endswith ".dll\"" or ProcessCommandLine endswith ".csproj'" or ProcessCommandLine endswith ".dll'") and (FolderPath endswith "\\dotnet.exe" or ProcessVersionInfoOriginalFileName =~ ".NET Host")) and (not(((ProcessCommandLine contains "C:\\ProgramData\\CSScriptNpp\\" and ProcessCommandLine contains "-cscs_path:" and ProcessCommandLine contains "\\cs-script\\cscs.dll") and (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Notepad++\\notepad++.exe", "C:\\Program Files\\Notepad++\\notepad++.exe")))))
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