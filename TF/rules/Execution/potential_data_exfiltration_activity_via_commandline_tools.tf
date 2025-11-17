resource "azurerm_sentinel_alert_rule_scheduled" "potential_data_exfiltration_activity_via_commandline_tools" {
  name                       = "potential_data_exfiltration_activity_via_commandline_tools"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Data Exfiltration Activity Via CommandLine Tools"
  description                = "Detects the use of various CLI utilities exfiltrating data via web requests - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains "curl " or ProcessCommandLine contains "Invoke-RestMethod" or ProcessCommandLine contains "Invoke-WebRequest" or ProcessCommandLine contains "irm " or ProcessCommandLine contains "iwr " or ProcessCommandLine contains "wget ") and (ProcessCommandLine contains " -ur" and ProcessCommandLine contains " -me" and ProcessCommandLine contains " -b" and ProcessCommandLine contains " POST ") and (FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\cmd.exe")) or ((ProcessCommandLine contains "--ur" and FolderPath endswith "\\curl.exe") and (ProcessCommandLine contains " -d " or ProcessCommandLine contains " --data ")) or ((ProcessCommandLine contains "--post-data" or ProcessCommandLine contains "--post-file") and FolderPath endswith "\\wget.exe")) and ((ProcessCommandLine matches regex "net\\s+view" or ProcessCommandLine matches regex "sc\\s+query") or (ProcessCommandLine contains "Get-Content" or ProcessCommandLine contains "GetBytes" or ProcessCommandLine contains "hostname" or ProcessCommandLine contains "ifconfig" or ProcessCommandLine contains "ipconfig" or ProcessCommandLine contains "netstat" or ProcessCommandLine contains "nltest" or ProcessCommandLine contains "qprocess" or ProcessCommandLine contains "systeminfo" or ProcessCommandLine contains "tasklist" or ProcessCommandLine contains "ToBase64String" or ProcessCommandLine contains "whoami") or (ProcessCommandLine contains "type " and ProcessCommandLine contains " > " and ProcessCommandLine contains " C:\\"))
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