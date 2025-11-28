resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_process_masquerading_as_svchost_exe" {
  name                       = "suspicious_process_masquerading_as_svchost_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Process Masquerading As SvcHost.EXE"
  description                = "Detects a suspicious process that is masquerading as the legitimate \"svchost.exe\" by naming its binary \"svchost.exe\" and executing from an uncommon location. Adversaries often disguise their malicious binaries by naming them after legitimate system processes like \"svchost.exe\" to evade detection. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\svchost.exe" and (not(((FolderPath in~ ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\SysWOW64\\svchost.exe")) or ProcessVersionInfoOriginalFileName =~ "svchost.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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