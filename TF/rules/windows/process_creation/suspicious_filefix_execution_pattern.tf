resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_filefix_execution_pattern" {
  name                       = "suspicious_filefix_execution_pattern"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious FileFix Execution Pattern"
  description                = "Detects suspicious FileFix execution patterns where users are tricked into running malicious commands through browser file upload dialog manipulation. This attack typically begins when users visit malicious websites impersonating legitimate services or news platforms, which may display fake CAPTCHA challenges or direct instructions to open file explorer and paste clipboard content. The clipboard content usually contains commands that download and execute malware, such as information stealing tools. - Legitimate use of PowerShell or other utilities launched from browser extensions or automation tools"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "#" and (InitiatingProcessFolderPath endswith "\\brave.exe" or InitiatingProcessFolderPath endswith "\\chrome.exe" or InitiatingProcessFolderPath endswith "\\firefox.exe" or InitiatingProcessFolderPath endswith "\\msedge.exe")) and ((ProcessCommandLine contains "account" or ProcessCommandLine contains "anti-bot" or ProcessCommandLine contains "botcheck" or ProcessCommandLine contains "captcha" or ProcessCommandLine contains "challenge" or ProcessCommandLine contains "confirmation" or ProcessCommandLine contains "fraud" or ProcessCommandLine contains "human" or ProcessCommandLine contains "identification" or ProcessCommandLine contains "identificator" or ProcessCommandLine contains "identity" or ProcessCommandLine contains "robot" or ProcessCommandLine contains "validation" or ProcessCommandLine contains "verification" or ProcessCommandLine contains "verify") or (ProcessCommandLine contains "%comspec%" or ProcessCommandLine contains "bitsadmin" or ProcessCommandLine contains "certutil" or ProcessCommandLine contains "cmd" or ProcessCommandLine contains "cscript" or ProcessCommandLine contains "curl" or ProcessCommandLine contains "finger" or ProcessCommandLine contains "mshta" or ProcessCommandLine contains "powershell" or ProcessCommandLine contains "pwsh" or ProcessCommandLine contains "regsvr32" or ProcessCommandLine contains "rundll32" or ProcessCommandLine contains "schtasks" or ProcessCommandLine contains "wget" or ProcessCommandLine contains "wscript"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1204"]
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