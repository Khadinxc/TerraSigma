resource "azurerm_sentinel_alert_rule_scheduled" "potential_winapi_calls_via_commandline" {
  name                       = "potential_winapi_calls_via_commandline"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential WinAPI Calls Via CommandLine"
  description                = "Detects the use of WinAPI Functions via the commandline. As seen used by threat actors via the tool winapiexec - Some legitimate action or applications may use these functions. Investigate further to determine the legitimacy of the activity."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "AddSecurityPackage" or ProcessCommandLine contains "AdjustTokenPrivileges" or ProcessCommandLine contains "Advapi32" or ProcessCommandLine contains "CloseHandle" or ProcessCommandLine contains "CreateProcessWithToken" or ProcessCommandLine contains "CreatePseudoConsole" or ProcessCommandLine contains "CreateRemoteThread" or ProcessCommandLine contains "CreateThread" or ProcessCommandLine contains "CreateUserThread" or ProcessCommandLine contains "DangerousGetHandle" or ProcessCommandLine contains "DuplicateTokenEx" or ProcessCommandLine contains "EnumerateSecurityPackages" or ProcessCommandLine contains "FreeHGlobal" or ProcessCommandLine contains "FreeLibrary" or ProcessCommandLine contains "GetDelegateForFunctionPointer" or ProcessCommandLine contains "GetLogonSessionData" or ProcessCommandLine contains "GetModuleHandle" or ProcessCommandLine contains "GetProcAddress" or ProcessCommandLine contains "GetProcessHandle" or ProcessCommandLine contains "GetTokenInformation" or ProcessCommandLine contains "ImpersonateLoggedOnUser" or ProcessCommandLine contains "kernel32" or ProcessCommandLine contains "LoadLibrary" or ProcessCommandLine contains "memcpy" or ProcessCommandLine contains "MiniDumpWriteDump" or ProcessCommandLine contains "ntdll" or ProcessCommandLine contains "OpenDesktop" or ProcessCommandLine contains "OpenProcess" or ProcessCommandLine contains "OpenProcessToken" or ProcessCommandLine contains "OpenThreadToken" or ProcessCommandLine contains "OpenWindowStation" or ProcessCommandLine contains "PtrToString" or ProcessCommandLine contains "QueueUserApc" or ProcessCommandLine contains "ReadProcessMemory" or ProcessCommandLine contains "RevertToSelf" or ProcessCommandLine contains "RtlCreateUserThread" or ProcessCommandLine contains "secur32" or ProcessCommandLine contains "SetThreadToken" or ProcessCommandLine contains "VirtualAlloc" or ProcessCommandLine contains "VirtualFree" or ProcessCommandLine contains "VirtualProtect" or ProcessCommandLine contains "WaitForSingleObject" or ProcessCommandLine contains "WriteInt32" or ProcessCommandLine contains "WriteProcessMemory" or ProcessCommandLine contains "ZeroFreeGlobalAllocUnicode") and (not((((ProcessCommandLine contains "FreeHGlobal" or ProcessCommandLine contains "PtrToString" or ProcessCommandLine contains "kernel32" or ProcessCommandLine contains "CloseHandle") and InitiatingProcessFolderPath endswith "\\CompatTelRunner.exe") or (ProcessCommandLine contains "GetLoadLibraryWAddress32" and FolderPath endswith "\\MpCmdRun.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1106"]
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