resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_mshta_susp_execution" {
  name                       = "proc_creation_win_mshta_susp_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "MSHTA Execution with Suspicious File Extensions"
  description                = <<DESC
    Detects execution of mshta.exe with file types that looks like they do not typically represent HTA (HTML Application) content, such as .png, .jpg, .zip, .pdf, and others, which are often polyglots. MSHTA is a legitimate Windows utility for executing HTML Applications containing VBScript or JScript. Threat actors often abuse this lolbin utility to download and execute malicious scripts disguised as benign files or hosted under misleading extensions to evade detection.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mshta_susp_execution.yml

    False Positives:
    - False positives depend on scripts and administrative tools used in the monitored environment
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".7z" or ProcessCommandLine contains ".avi" or ProcessCommandLine contains ".bat" or ProcessCommandLine contains ".bmp" or ProcessCommandLine contains ".conf" or ProcessCommandLine contains ".csv" or ProcessCommandLine contains ".dll" or ProcessCommandLine contains ".doc" or ProcessCommandLine contains ".gif" or ProcessCommandLine contains ".gz" or ProcessCommandLine contains ".ini" or ProcessCommandLine contains ".jpe" or ProcessCommandLine contains ".jpg" or ProcessCommandLine contains ".json" or ProcessCommandLine contains ".lnk" or ProcessCommandLine contains ".log" or ProcessCommandLine contains ".mkv" or ProcessCommandLine contains ".mp3" or ProcessCommandLine contains ".mp4" or ProcessCommandLine contains ".pdf" or ProcessCommandLine contains ".png" or ProcessCommandLine contains ".ppt" or ProcessCommandLine contains ".rar" or ProcessCommandLine contains ".rtf" or ProcessCommandLine contains ".svg" or ProcessCommandLine contains ".tar" or ProcessCommandLine contains ".tmp" or ProcessCommandLine contains ".txt" or ProcessCommandLine contains ".xls" or ProcessCommandLine contains ".xml" or ProcessCommandLine contains ".yaml" or ProcessCommandLine contains ".yml" or ProcessCommandLine contains ".zip" or ProcessCommandLine contains "vbscript") and (FolderPath endswith "\\mshta.exe" or ProcessVersionInfoOriginalFileName =~ "mshta.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1140", "T1218", "T1059"]
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