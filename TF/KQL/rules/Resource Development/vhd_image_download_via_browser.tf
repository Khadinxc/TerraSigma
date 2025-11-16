resource "azurerm_sentinel_alert_rule_scheduled" "vhd_image_download_via_browser" {
  name                       = "vhd_image_download_via_browser"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "VHD Image Download Via Browser"
  description                = "Detects creation of \".vhd\"/\".vhdx\" files by browser processes. Malware can use mountable Virtual Hard Disk \".vhd\" files to encapsulate payloads and evade security controls. - Legitimate downloads of \".vhd\" files would also trigger this"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\brave.exe" or InitiatingProcessFolderPath endswith "\\chrome.exe" or InitiatingProcessFolderPath endswith "\\firefox.exe" or InitiatingProcessFolderPath endswith "\\iexplore.exe" or InitiatingProcessFolderPath endswith "\\maxthon.exe" or InitiatingProcessFolderPath endswith "\\MicrosoftEdge.exe" or InitiatingProcessFolderPath endswith "\\msedge.exe" or InitiatingProcessFolderPath endswith "\\msedgewebview2.exe" or InitiatingProcessFolderPath endswith "\\opera.exe" or InitiatingProcessFolderPath endswith "\\safari.exe" or InitiatingProcessFolderPath endswith "\\seamonkey.exe" or InitiatingProcessFolderPath endswith "\\vivaldi.exe" or InitiatingProcessFolderPath endswith "\\whale.exe") and FolderPath contains ".vhd"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["ResourceDevelopment"]
  techniques                 = ["T1587"]
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
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}