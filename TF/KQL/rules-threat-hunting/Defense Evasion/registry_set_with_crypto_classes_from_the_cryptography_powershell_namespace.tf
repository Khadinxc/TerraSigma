resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_with_crypto_classes_from_the_cryptography_powershell_namespace" {
  name                       = "registry_set_with_crypto_classes_from_the_cryptography_powershell_namespace"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Set With Crypto-Classes From The \"Cryptography\" PowerShell Namespace"
  description                = "Detects the setting of a registry inside the \"\\Shell\\Open\\Command\" value with PowerShell classes from the \"System.Security.Cryptography\" namespace. The PowerShell namespace \"System.Security.Cryptography\" provides classes for on-the-fly encryption and decryption. These can be used for example in decrypting malicious payload for defense evasion. - Classes are legitimately used, but less so when e.g. parents with low prevalence or decryption of content in temporary folders."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\Shell\\Open\\Command" and (RegistryValueData contains ".AesCryptoServiceProvider" or RegistryValueData contains ".DESCryptoServiceProvider" or RegistryValueData contains ".DSACryptoServiceProvider" or RegistryValueData contains ".RC2CryptoServiceProvider" or RegistryValueData contains ".Rijndael" or RegistryValueData contains ".RSACryptoServiceProvider" or RegistryValueData contains ".TripleDESCryptoServiceProvider") and (RegistryValueData contains "powershell" or RegistryValueData contains "pwsh") and RegistryValueData contains "System.Security.Cryptography."
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1059", "T1027", "T1547"]
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
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}