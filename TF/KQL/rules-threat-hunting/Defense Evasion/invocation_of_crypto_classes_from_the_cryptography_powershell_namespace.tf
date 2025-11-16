resource "azurerm_sentinel_alert_rule_scheduled" "invocation_of_crypto_classes_from_the_cryptography_powershell_namespace" {
  name                       = "invocation_of_crypto_classes_from_the_cryptography_powershell_namespace"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Invocation Of Crypto-Classes From The \"Cryptography\" PowerShell Namespace"
  description                = "Detects the invocation of PowerShell commands with references to classes from the \"System.Security.Cryptography\" namespace. The PowerShell namespace \"System.Security.Cryptography\" provides classes for on-the-fly encryption and decryption. These can be used for example in decrypting malicious payload for defense evasion. - Classes are legitimately used, but less so when e.g. parents with low prevalence or decryption of content in temporary folders."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".AesCryptoServiceProvider" or ProcessCommandLine contains ".DESCryptoServiceProvider" or ProcessCommandLine contains ".DSACryptoServiceProvider" or ProcessCommandLine contains ".RC2CryptoServiceProvider" or ProcessCommandLine contains ".Rijndael" or ProcessCommandLine contains ".RSACryptoServiceProvider" or ProcessCommandLine contains ".TripleDESCryptoServiceProvider") and ProcessCommandLine contains "System.Security.Cryptography." and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1059", "T1027"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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