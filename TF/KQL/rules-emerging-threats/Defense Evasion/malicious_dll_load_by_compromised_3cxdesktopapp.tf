resource "azurerm_sentinel_alert_rule_scheduled" "malicious_dll_load_by_compromised_3cxdesktopapp" {
  name                       = "malicious_dll_load_by_compromised_3cxdesktopapp"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Malicious DLL Load By Compromised 3CXDesktopApp"
  description                = "Detects DLL load activity of known compromised DLLs used in by the compromised 3CXDesktopApp - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (SHA256 startswith "7986BBAEE8940DA11CE089383521AB420C443AB7B15ED42AED91FD31CE833896" or SHA256 startswith "11BE1803E2E307B647A8A7E02D128335C448FF741BF06BF52B332E0BBF423B03" or SHA256 startswith "F79C3B0ADB6EC7BCC8BC9AE955A1571AAED6755A28C8B17B1D7595EE86840952" or SHA256 startswith "8AB3A5EAAF8C296080FADF56B265194681D7DA5DA7C02562953A4CB60E147423") or (SHA1 startswith "BF939C9C261D27EE7BB92325CC588624FCA75429" or SHA1 startswith "20D554A80D759C50D6537DD7097FED84DD258B3E" or SHA1 startswith "894E7D4FFD764BB458809C7F0643694B036EAD30" or SHA1 startswith "3B3E778B647371262120A523EB873C20BB82BEAF") or (MD5 startswith "74BC2D0B6680FAA1A5A76B27E5479CBC" or MD5 startswith "82187AD3F0C6C225E2FBA0C867280CC9" or MD5 startswith "11BC82A9BD8297BD0823BCE5D6202082" or MD5 startswith "7FAEA2B01796B80D180399040BB69835")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "SHA1"
      column_name = "SHA1"
    }
    field_mapping {
      identifier  = "SHA256"
      column_name = "SHA256"
    }
    field_mapping {
      identifier  = "MD5"
      column_name = "MD5"
    }
  }
}