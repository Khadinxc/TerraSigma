resource "azurerm_sentinel_alert_rule_scheduled" "dll_call_by_ordinal_via_rundll32_exe" {
  name                       = "dll_call_by_ordinal_via_rundll32_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DLL Call by Ordinal Via Rundll32.EXE"
  description                = "Detects calls of DLLs exports by ordinal numbers via rundll32.dll. - Windows control panel elements have been identified as source (mmc)."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains ",#" or ProcessCommandLine contains ", #" or ProcessCommandLine contains ".dll #" or ProcessCommandLine contains ".ocx #") and (FolderPath endswith "\\rundll32.exe" or ProcessVersionInfoOriginalFileName =~ "RUNDLL32.EXE")) and (not(((ProcessCommandLine contains "EDGEHTML.dll" and ProcessCommandLine contains "#141") or ((ProcessCommandLine contains "\\FileTracker32.dll,#1" or ProcessCommandLine contains "\\FileTracker32.dll\",#1" or ProcessCommandLine contains "\\FileTracker64.dll,#1" or ProcessCommandLine contains "\\FileTracker64.dll\",#1") and (InitiatingProcessFolderPath contains "\\Msbuild\\Current\\Bin\\" or InitiatingProcessFolderPath contains "\\VC\\Tools\\MSVC\\" or InitiatingProcessFolderPath contains "\\Tracker.exe")))))
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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