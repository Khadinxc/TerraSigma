resource "azurerm_sentinel_alert_rule_scheduled" "uac_secure_desktop_prompt_disabled" {
  name                       = "uac_secure_desktop_prompt_disabled"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UAC Secure Desktop Prompt Disabled"
  description                = "Detects when an attacker tries to change User Account Control (UAC) elevation request destination via the \"PromptOnSecureDesktop\" value. The \"PromptOnSecureDesktop\" setting specifically determines whether UAC prompts are displayed on the secure desktop. The secure desktop is a separate desktop environment that's isolated from other processes running on the system. It's designed to prevent malicious software from intercepting or tampering with UAC prompts. When \"PromptOnSecureDesktop\" is set to 0, UAC prompts are displayed on the user's current desktop instead of the secure desktop. This reduces the level of security because it potentially exposes the prompts to manipulation by malicious software."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000000)" and RegistryKey contains "\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1548"]
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