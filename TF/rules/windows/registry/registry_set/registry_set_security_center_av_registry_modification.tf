resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_security_center_av_registry_modification" {
  name                       = "registry_set_security_center_av_registry_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential HackTool - Defendnot Security Center AV Registry Modification"
  description                = <<DESC
    Detects modification of the Microsoft Security Center AV registry keys, particularly those related with DisplayName, ProductEXE, or ReportingExe. These keys typically store information about antivirus products installed on the system, which is Windows Defender or third-party antivirus software. But, if these keys holds unexpected values or are modified in a suspicious manner, it could indicate an attempt to tamper with the security settings of the system.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_security_center_av_registry_modification.yml

    False Positives:
    - Legitimate changes by antivirus software missing in the filter list
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\Software\\Microsoft\\Security Center\\Provider\\Av*" and (RegistryKey endswith "\\ProductEXE" or RegistryKey endswith "\\DisplayName" or RegistryKey endswith "\\ReportingExe")) and (not(((RegistryValueData contains "Avira" or RegistryValueData contains "Windows Defender" or RegistryValueData contains "Microsoft Defender" or RegistryValueData contains "Sophos" or RegistryValueData contains "Kaspersky" or RegistryValueData contains "ESET" or RegistryValueData contains "Bitdefender" or RegistryValueData contains "Trend Micro" or RegistryValueData contains "McAfee" or RegistryValueData contains "Symantec" or RegistryValueData contains "CrowdStrike" or RegistryValueData contains "SentinelOne" or RegistryValueData contains "Carbon Black" or RegistryValueData contains "Elastic" or RegistryValueData contains "Cortex" or RegistryValueData contains "AVG" or RegistryValueData contains "Avast" or RegistryValueData contains "Malwarebytes") and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\svchost.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  techniques                 = ["T1685"]
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }

  entity_mapping {
    entity_type = "RegistryValue"
    field_mapping {
      identifier  = "Value"
      column_name = "RegistryValueData"
    }
  }
}