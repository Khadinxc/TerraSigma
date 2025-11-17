resource "azurerm_sentinel_alert_rule_scheduled" "potential_clickfix_execution_pattern_registry" {
  name                       = "potential_clickfix_execution_pattern_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential ClickFix Execution Pattern - Registry"
  description                = "Detects potential ClickFix malware execution patterns by monitoring registry modifications in RunMRU keys containing HTTP/HTTPS links. ClickFix is known to be distributed through phishing campaigns and uses techniques like clipboard hijacking and fake CAPTCHA pages. Through the fakecaptcha pages, the adversary tricks users into opening the Run dialog box and pasting clipboard-hijacked content, such as one-liners that execute remotely hosted malicious files or scripts. - Legitimate applications using RunMRU with HTTP links"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains "http://" or RegistryValueData contains "https://") and RegistryKey endswith "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU*" and ((RegistryValueData contains "account" or RegistryValueData contains "anti-bot" or RegistryValueData contains "botcheck" or RegistryValueData contains "captcha" or RegistryValueData contains "challenge" or RegistryValueData contains "confirmation" or RegistryValueData contains "fraud" or RegistryValueData contains "human" or RegistryValueData contains "identificator" or RegistryValueData contains "identity" or RegistryValueData contains "robot" or RegistryValueData contains "validation" or RegistryValueData contains "verification" or RegistryValueData contains "verify") or (RegistryValueData contains "%comspec%" or RegistryValueData contains "bitsadmin" or RegistryValueData contains "certutil" or RegistryValueData contains "cmd" or RegistryValueData contains "cscript" or RegistryValueData contains "curl" or RegistryValueData contains "mshta" or RegistryValueData contains "powershell" or RegistryValueData contains "pwsh" or RegistryValueData contains "regsvr32" or RegistryValueData contains "rundll32" or RegistryValueData contains "schtasks" or RegistryValueData contains "wget" or RegistryValueData contains "wscript"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1204"]
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