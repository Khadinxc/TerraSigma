resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_rundll32_activity" {
  name                       = "potentially_suspicious_rundll32_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Rundll32 Activity"
  description                = "Detects suspicious execution of rundll32, with specific calls to some DLLs with known LOLBIN functionalities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "javascript:" and ProcessCommandLine contains ".RegisterXLL") or (ProcessCommandLine contains "url.dll" and ProcessCommandLine contains "OpenURL") or (ProcessCommandLine contains "url.dll" and ProcessCommandLine contains "OpenURLA") or (ProcessCommandLine contains "url.dll" and ProcessCommandLine contains "FileProtocolHandler") or (ProcessCommandLine contains "zipfldr.dll" and ProcessCommandLine contains "RouteTheCall") or (ProcessCommandLine contains "shell32.dll" and ProcessCommandLine contains "Control_RunDLL") or (ProcessCommandLine contains "shell32.dll" and ProcessCommandLine contains "ShellExec_RunDLL") or (ProcessCommandLine contains "mshtml.dll" and ProcessCommandLine contains "PrintHTML") or (ProcessCommandLine contains "advpack.dll" and ProcessCommandLine contains "LaunchINFSection") or (ProcessCommandLine contains "advpack.dll" and ProcessCommandLine contains "RegisterOCX") or (ProcessCommandLine contains "ieadvpack.dll" and ProcessCommandLine contains "LaunchINFSection") or (ProcessCommandLine contains "ieadvpack.dll" and ProcessCommandLine contains "RegisterOCX") or (ProcessCommandLine contains "ieframe.dll" and ProcessCommandLine contains "OpenURL") or (ProcessCommandLine contains "shdocvw.dll" and ProcessCommandLine contains "OpenURL") or (ProcessCommandLine contains "syssetup.dll" and ProcessCommandLine contains "SetupInfObjectInstallAction") or (ProcessCommandLine contains "setupapi.dll" and ProcessCommandLine contains "InstallHinfSection") or (ProcessCommandLine contains "pcwutl.dll" and ProcessCommandLine contains "LaunchApplication") or (ProcessCommandLine contains "dfshim.dll" and ProcessCommandLine contains "ShOpenVerbApplication") or (ProcessCommandLine contains "dfshim.dll" and ProcessCommandLine contains "ShOpenVerbShortcut") or (ProcessCommandLine contains "scrobj.dll" and ProcessCommandLine contains "GenerateTypeLib" and ProcessCommandLine contains "http") or (ProcessCommandLine contains "shimgvw.dll" and ProcessCommandLine contains "ImageView_Fullscreen" and ProcessCommandLine contains "http") or (ProcessCommandLine contains "comsvcs.dll" and ProcessCommandLine contains "MiniDump")) and (not((((ProcessCommandLine contains "Shell32.dll" and ProcessCommandLine contains "Control_RunDLL" and ProcessCommandLine contains ".cpl") and InitiatingProcessCommandLine contains ".cpl" and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\control.exe") or ProcessCommandLine contains "shell32.dll,Control_RunDLL desk.cpl,screensaver,@screensaver" or (ProcessCommandLine endswith ".cpl\"," and ProcessCommandLine startswith "\"C:\\Windows\\system32\\rundll32.exe\" Shell32.dll,Control_RunDLL \"C:\\Windows\\System32\\" and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\control.exe"))))
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}