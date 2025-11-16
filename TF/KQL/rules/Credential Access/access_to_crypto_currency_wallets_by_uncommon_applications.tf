resource "azurerm_sentinel_alert_rule_scheduled" "access_to_crypto_currency_wallets_by_uncommon_applications" {
  name                       = "access_to_crypto_currency_wallets_by_uncommon_applications"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Access To Crypto Currency Wallets By Uncommon Applications"
  description                = "Detects file access requests to crypto currency files by uncommon processes. Could indicate potential attempt of crypto currency wallet stealing. - Antivirus, Anti-Spyware, Anti-Malware Software - Backup software - Legitimate software installed on partitions other than \"C:\\\" - Searching software such as \"everything.exe\""
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where ((FileName contains "\\AppData\\Roaming\\Ethereum\\keystore\\" or FileName contains "\\AppData\\Roaming\\EthereumClassic\\keystore\\" or FileName contains "\\AppData\\Roaming\\monero\\wallets\\") or (FileName endswith "\\AppData\\Roaming\\Bitcoin\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\BitcoinABC\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\BitcoinSV\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\DashCore\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\DogeCoin\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\Litecoin\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\Ripple\\wallet.dat" or FileName endswith "\\AppData\\Roaming\\Zcash\\wallet.dat")) and (not(((InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\system32\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\SysWOW64\\") or InitiatingProcessFolderPath =~ "System"))) and (not(((InitiatingProcessFolderPath endswith "\\MpCopyAccelerator.exe" or InitiatingProcessFolderPath endswith "\\MsMpEng.exe") and InitiatingProcessFolderPath startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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