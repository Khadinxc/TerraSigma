resource "azurerm_sentinel_alert_rule_scheduled" "registry_manipulation_via_wmi_stdregprov" {
  name                       = "registry_manipulation_via_wmi_stdregprov"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Manipulation via WMI Stdregprov"
  description                = "Detects the usage of wmic.exe to manipulate Windows registry via the WMI StdRegProv class. This behaviour could be potentially suspicious because it uses an alternative method to modify registry keys instead of legitimate registry tools like reg.exe or regedit.exe. Attackers specifically choose this technique to evade detection and bypass security monitoring focused on traditional registry modification commands. - Legitimate administrative activity"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "call" and ProcessCommandLine contains "stdregprov") and (FolderPath endswith "\\wmic.exe" or ProcessVersionInfoOriginalFileName =~ "wmic.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "Execution", "DefenseEvasion", "Discovery"]
  techniques                 = ["T1047", "T1112", "T1012"]
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