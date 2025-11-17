resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_serv_u_process_pattern" {
  name                       = "suspicious_serv_u_process_pattern"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Serv-U Process Pattern"
  description                = "Detects a suspicious process pattern which could be a sign of an exploited Serv-U service - Legitimate uses in which users or programs use the SSH service of Serv-U for remote command execution"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\sh.exe" or FolderPath endswith "\\bash.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\msiexec.exe" or FolderPath endswith "\\forfiles.exe" or FolderPath endswith "\\scriptrunner.exe") and InitiatingProcessFolderPath endswith "\\Serv-U.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1555"]
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