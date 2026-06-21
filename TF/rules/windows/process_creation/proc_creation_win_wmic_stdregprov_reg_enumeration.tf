resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_wmic_stdregprov_reg_enumeration" {
  name                       = "proc_creation_win_wmic_stdregprov_reg_enumeration"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Enumeration via WMI Stdregprov"
  description                = <<DESC
    Detects the usage of wmic.exe to enumerate or read Windows registry via the WMI StdRegProv class read methods (EnumKey, EnumValues, GetStringValue, etc.). While registry reads are common, attackers may use this technique to perform reconnaissance and discover sensitive configuration values, credentials, or installed software. The use of WMI as an alternative to standard tools like reg.exe can indicate an attempt to evade detection focused on traditional registry query commands.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wmic_stdregprov_reg_enumeration.yml

    False Positives:
    - Legitimate administrative activity
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "CheckAccess" or ProcessCommandLine contains "EnumKey" or ProcessCommandLine contains "EnumValues" or ProcessCommandLine contains "GetBinaryValue" or ProcessCommandLine contains "GetDWORDValue" or ProcessCommandLine contains "GetExpandedStringValue" or ProcessCommandLine contains "GetMultiStringValue" or ProcessCommandLine contains "GetQWORDValue" or ProcessCommandLine contains "GetSecurityDescriptor" or ProcessCommandLine contains "GetStringValue") and (ProcessCommandLine contains "stdregprov" and ProcessCommandLine contains "call")) and (FolderPath endswith "\\wmic.exe" or ProcessVersionInfoOriginalFileName =~ "wmic.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Discovery"]
  techniques                 = ["T1047", "T1012"]
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