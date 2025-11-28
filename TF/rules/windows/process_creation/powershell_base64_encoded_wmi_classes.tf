resource "azurerm_sentinel_alert_rule_scheduled" "powershell_base64_encoded_wmi_classes" {
  name                       = "powershell_base64_encoded_wmi_classes"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Base64 Encoded WMI Classes"
  description                = "Detects calls to base64 encoded WMI class such as \"Win32_ShadowCopy\", \"Win32_ScheduledJob\", etc."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll"))) and ((ProcessCommandLine contains "VwBpAG4AMwAyAF8ATABvAGcAZwBlAGQATwBuAFUAcwBlAHIA" or ProcessCommandLine contains "cAaQBuADMAMgBfAEwAbwBnAGcAZQBkAE8AbgBVAHMAZQByA" or ProcessCommandLine contains "XAGkAbgAzADIAXwBMAG8AZwBnAGUAZABPAG4AVQBzAGUAcg" or ProcessCommandLine contains "V2luMzJfTG9nZ2VkT25Vc2Vy" or ProcessCommandLine contains "dpbjMyX0xvZ2dlZE9uVXNlc" or ProcessCommandLine contains "XaW4zMl9Mb2dnZWRPblVzZX") or (ProcessCommandLine contains "VwBpAG4AMwAyAF8AUAByAG8AYwBlAHMAcw" or ProcessCommandLine contains "cAaQBuADMAMgBfAFAAcgBvAGMAZQBzAHMA" or ProcessCommandLine contains "XAGkAbgAzADIAXwBQAHIAbwBjAGUAcwBzA" or ProcessCommandLine contains "V2luMzJfUHJvY2Vzc" or ProcessCommandLine contains "dpbjMyX1Byb2Nlc3" or ProcessCommandLine contains "XaW4zMl9Qcm9jZXNz") or (ProcessCommandLine contains "VwBpAG4AMwAyAF8AUwBjAGgAZQBkAHUAbABlAGQASgBvAGIA" or ProcessCommandLine contains "cAaQBuADMAMgBfAFMAYwBoAGUAZAB1AGwAZQBkAEoAbwBiA" or ProcessCommandLine contains "XAGkAbgAzADIAXwBTAGMAaABlAGQAdQBsAGUAZABKAG8AYg" or ProcessCommandLine contains "V2luMzJfU2NoZWR1bGVkSm9i" or ProcessCommandLine contains "dpbjMyX1NjaGVkdWxlZEpvY" or ProcessCommandLine contains "XaW4zMl9TY2hlZHVsZWRKb2") or (ProcessCommandLine contains "VwBpAG4AMwAyAF8AUwBoAGEAZABvAHcAYwBvAHAAeQ" or ProcessCommandLine contains "cAaQBuADMAMgBfAFMAaABhAGQAbwB3AGMAbwBwAHkA" or ProcessCommandLine contains "XAGkAbgAzADIAXwBTAGgAYQBkAG8AdwBjAG8AcAB5A" or ProcessCommandLine contains "V2luMzJfU2hhZG93Y29we" or ProcessCommandLine contains "dpbjMyX1NoYWRvd2NvcH" or ProcessCommandLine contains "XaW4zMl9TaGFkb3djb3B5") or (ProcessCommandLine contains "VwBpAG4AMwAyAF8AVQBzAGUAcgBBAGMAYwBvAHUAbgB0A" or ProcessCommandLine contains "cAaQBuADMAMgBfAFUAcwBlAHIAQQBjAGMAbwB1AG4AdA" or ProcessCommandLine contains "XAGkAbgAzADIAXwBVAHMAZQByAEEAYwBjAG8AdQBuAHQA" or ProcessCommandLine contains "V2luMzJfVXNlckFjY291bn" or ProcessCommandLine contains "dpbjMyX1VzZXJBY2NvdW50" or ProcessCommandLine contains "XaW4zMl9Vc2VyQWNjb3Vud"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1059", "T1027"]
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