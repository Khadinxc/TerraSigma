resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_powershell_base64_iex" {
  name                       = "proc_creation_win_powershell_base64_iex"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Base64 Encoded IEX Cmdlet"
  description                = <<DESC
    Detects usage of a base64 encoded "IEX" cmdlet in a process command line

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_base64_iex.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "SUVYIChb" or ProcessCommandLine contains "lFWCAoW" or ProcessCommandLine contains "JRVggKF" or ProcessCommandLine contains "aWV4IChb" or ProcessCommandLine contains "lleCAoW" or ProcessCommandLine contains "pZXggKF" or ProcessCommandLine contains "aWV4IChOZX" or ProcessCommandLine contains "lleCAoTmV3" or ProcessCommandLine contains "pZXggKE5ld" or ProcessCommandLine contains "SUVYIChOZX" or ProcessCommandLine contains "lFWCAoTmV3" or ProcessCommandLine contains "JRVggKE5ld" or ProcessCommandLine contains "SUVYKF" or ProcessCommandLine contains "lFWChb" or ProcessCommandLine contains "JRVgoW" or ProcessCommandLine contains "aWV4KF" or ProcessCommandLine contains "lleChb" or ProcessCommandLine contains "pZXgoW" or ProcessCommandLine contains "aWV4KE5ld" or ProcessCommandLine contains "lleChOZX" or ProcessCommandLine contains "pZXgoTmV3" or ProcessCommandLine contains "SUVYKE5ld" or ProcessCommandLine contains "lFWChOZX" or ProcessCommandLine contains "JRVgoTmV3" or ProcessCommandLine contains "SUVYKCgn" or ProcessCommandLine contains "lFWCgoJ" or ProcessCommandLine contains "JRVgoKC" or ProcessCommandLine contains "aWV4KCgn" or ProcessCommandLine contains "lleCgoJ" or ProcessCommandLine contains "pZXgoKC") or (ProcessCommandLine contains "SQBFAFgAIAAoAFsA" or ProcessCommandLine contains "kARQBYACAAKABbA" or ProcessCommandLine contains "JAEUAWAAgACgAWw" or ProcessCommandLine contains "aQBlAHgAIAAoAFsA" or ProcessCommandLine contains "kAZQB4ACAAKABbA" or ProcessCommandLine contains "pAGUAeAAgACgAWw" or ProcessCommandLine contains "aQBlAHgAIAAoAE4AZQB3A" or ProcessCommandLine contains "kAZQB4ACAAKABOAGUAdw" or ProcessCommandLine contains "pAGUAeAAgACgATgBlAHcA" or ProcessCommandLine contains "SQBFAFgAIAAoAE4AZQB3A" or ProcessCommandLine contains "kARQBYACAAKABOAGUAdw" or ProcessCommandLine contains "JAEUAWAAgACgATgBlAHcA")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
}