resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_child_process_of_appvlp_exe" {
  name                       = "uncommon_child_process_of_appvlp_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon Child Process Of Appvlp.EXE"
  description                = "Detects uncommon child processes of Appvlp.EXE Appvlp or the Application Virtualization Utility is included with Microsoft Office. Attackers are able to abuse \"AppVLP\" to execute shell commands. Normally, this binary is used for Application Virtualization, but it can also be abused to circumvent the ASR file path rule folder or to mark a file as a system file."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\appvlp.exe" and (not((FolderPath endswith ":\\Windows\\SysWOW64\\rundll32.exe" or FolderPath endswith ":\\Windows\\System32\\rundll32.exe"))) and (not(((FolderPath contains ":\\Program Files\\Microsoft Office" and FolderPath endswith "\\msoasb.exe") or (FolderPath contains ":\\Program Files\\Microsoft Office" and FolderPath endswith "\\MSOUC.EXE") or ((FolderPath contains ":\\Program Files\\Microsoft Office" and FolderPath contains "\\SkypeSrv\\") and FolderPath endswith "\\SKYPESERVER.EXE"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}