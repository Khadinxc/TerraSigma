resource "azurerm_sentinel_alert_rule_scheduled" "darkgate_autoit3_exe_execution_parameters" {
  name                       = "darkgate_autoit3_exe_execution_parameters"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DarkGate - Autoit3.EXE Execution Parameters"
  description                = "Detects execution of the legitimate Autoit3 utility from a suspicious parent process. AutoIt3.exe is used within the DarkGate infection chain to execute shellcode that performs process injection and connects to the DarkGate command-and-control server. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((InitiatingProcessFolderPath endswith "\\cmd.exe" or InitiatingProcessFolderPath endswith "\\KeyScramblerLogon.exe" or InitiatingProcessFolderPath endswith "\\msiexec.exe") and (FolderPath endswith "\\Autoit3.exe" or ProcessVersionInfoOriginalFileName =~ "AutoIt3.exe")) and (not((FolderPath endswith ":\\Program Files (x86)\\AutoIt3\\AutoIt3.exe" or FolderPath endswith ":\\Program Files\\AutoIt3\\AutoIt3.exe")))
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