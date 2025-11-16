resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_git_clone" {
  name                       = "suspicious_git_clone"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Git Clone"
  description                = "Detects execution of \"git\" in order to clone a remote repository that contain suspicious keywords which might be suspicious"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " clone " or ProcessCommandLine contains "git-remote-https ") and ((FolderPath endswith "\\git.exe" or FolderPath endswith "\\git-remote-https.exe") or ProcessVersionInfoOriginalFileName =~ "git.exe") and (ProcessCommandLine contains "exploit" or ProcessCommandLine contains "Vulns" or ProcessCommandLine contains "vulnerability" or ProcessCommandLine contains "RemoteCodeExecution" or ProcessCommandLine contains "Invoke-" or ProcessCommandLine contains "CVE-" or ProcessCommandLine contains "poc-" or ProcessCommandLine contains "ProofOfConcept" or ProcessCommandLine contains "proxyshell" or ProcessCommandLine contains "log4shell" or ProcessCommandLine contains "eternalblue" or ProcessCommandLine contains "eternal-blue" or ProcessCommandLine contains "MS17-")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Reconnaissance"]
  techniques                 = ["T1593"]
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