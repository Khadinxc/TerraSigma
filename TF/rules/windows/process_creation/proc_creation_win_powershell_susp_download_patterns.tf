resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_powershell_susp_download_patterns" {
  name                       = "proc_creation_win_powershell_susp_download_patterns"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious PowerShell Download and Execute Pattern"
  description                = "Detects suspicious PowerShell download patterns that are often used in malicious scripts, stagers or downloaders (make sure that your backend applies the strings case-insensitive) Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_susp_download_patterns.yml - Software installers that pull packages from remote systems and execute them | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_susp_download_patterns.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "IEX ((New-Object Net.WebClient).DownloadString" or ProcessCommandLine contains "IEX (New-Object Net.WebClient).DownloadString" or ProcessCommandLine contains "IEX((New-Object Net.WebClient).DownloadString" or ProcessCommandLine contains "IEX(New-Object Net.WebClient).DownloadString" or ProcessCommandLine contains " -command (New-Object System.Net.WebClient).DownloadFile(" or ProcessCommandLine contains " -c (New-Object System.Net.WebClient).DownloadFile("
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