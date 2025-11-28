resource "azurerm_sentinel_alert_rule_scheduled" "windows_default_domain_gpo_modification_via_gpme" {
  name                       = "windows_default_domain_gpo_modification_via_gpme"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Default Domain GPO Modification via GPME"
  description                = "Detects the use of the Group Policy Management Editor (GPME) to modify Default Domain or Default Domain Controllers Group Policy Objects (GPOs). Adversaries may leverage GPME to make stealthy changes in these default GPOs to deploy malicious GPOs configurations across the domain without raising suspicion. - Legitimate use of GPME to modify GPOs"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "31B2F340-016D-11D2-945F-00C04FB984F9" or ProcessCommandLine contains "6AC1786C-016F-11D2-945F-00C04FB984F9") and (ProcessCommandLine contains "gpme.msc" and ProcessCommandLine contains "gpobject:") and (FolderPath endswith "\\mmc.exe" or ProcessVersionInfoOriginalFileName =~ "MMC.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1484"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}