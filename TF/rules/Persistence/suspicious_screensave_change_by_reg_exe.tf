resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_screensave_change_by_reg_exe" {
  name                       = "suspicious_screensave_change_by_reg_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious ScreenSave Change by Reg.exe"
  description                = "Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension - GPO"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "HKEY_CURRENT_USER\\Control Panel\\Desktop" or ProcessCommandLine contains "HKCU\\Control Panel\\Desktop") and FolderPath endswith "\\reg.exe") and ((ProcessCommandLine contains "/v ScreenSaveActive" and ProcessCommandLine contains "/t REG_SZ" and ProcessCommandLine contains "/d 1" and ProcessCommandLine contains "/f") or (ProcessCommandLine contains "/v ScreenSaveTimeout" and ProcessCommandLine contains "/t REG_SZ" and ProcessCommandLine contains "/d " and ProcessCommandLine contains "/f") or (ProcessCommandLine contains "/v ScreenSaverIsSecure" and ProcessCommandLine contains "/t REG_SZ" and ProcessCommandLine contains "/d 0" and ProcessCommandLine contains "/f") or (ProcessCommandLine contains "/v SCRNSAVE.EXE" and ProcessCommandLine contains "/t REG_SZ" and ProcessCommandLine contains "/d " and ProcessCommandLine contains ".scr" and ProcessCommandLine contains "/f"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1546"]
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