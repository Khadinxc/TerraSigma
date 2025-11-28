resource "azurerm_sentinel_alert_rule_scheduled" "wdac_policy_file_creation_in_codeintegrity_folder" {
  name                       = "wdac_policy_file_creation_in_codeintegrity_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WDAC Policy File Creation In CodeIntegrity Folder"
  description                = "Attackers can craft a custom Windows Defender Application Control (WDAC) policy that blocks Endpoint Detection and Response (EDR) components while allowing their own malicious code. The policy is placed in the privileged Windows Code Integrity folder (C:\\Windows\\System32\\CodeIntegrity\\). Upon reboot, the policy prevents EDR drivers from loading, effectively bypassing security measures and may further enable undetected lateral movement within an Active Directory environment. - May occur legitimately as part of admin activity, but rarely with interactive elevation."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessIntegrityLevel =~ "High" and FolderPath contains ":\\Windows\\System32\\CodeIntegrity\\" and (FolderPath endswith ".cip" or FolderPath endswith ".p7b")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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