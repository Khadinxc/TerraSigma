resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_certutil_download_direct_ip" {
  name                       = "proc_creation_win_certutil_download_direct_ip"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious File Downloaded From Direct IP Via Certutil.EXE"
  description                = <<DESC
    Detects the execution of certutil with certain flags that allow the utility to download files from direct IPs.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certutil_download_direct_ip.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "urlcache " or ProcessCommandLine contains "verifyctl " or ProcessCommandLine contains "URL ") and (ProcessCommandLine contains "://1" or ProcessCommandLine contains "://2" or ProcessCommandLine contains "://3" or ProcessCommandLine contains "://4" or ProcessCommandLine contains "://5" or ProcessCommandLine contains "://6" or ProcessCommandLine contains "://7" or ProcessCommandLine contains "://8" or ProcessCommandLine contains "://9") and (FolderPath endswith "\\certutil.exe" or ProcessVersionInfoOriginalFileName =~ "CertUtil.exe")) and (not(ProcessCommandLine contains "://7-"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CommandAndControl"]
  techniques                 = ["T1027", "T1105"]
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