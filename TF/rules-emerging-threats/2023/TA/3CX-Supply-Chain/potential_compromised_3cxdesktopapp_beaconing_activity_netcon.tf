resource "azurerm_sentinel_alert_rule_scheduled" "potential_compromised_3cxdesktopapp_beaconing_activity_netcon" {
  name                       = "potential_compromised_3cxdesktopapp_beaconing_activity_netcon"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Compromised 3CXDesktopApp Beaconing Activity - Netcon"
  description                = "Detects potential beaconing activity to domains related to 3CX 3CXDesktopApp compromise - Unlikely | Source: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2023/TA/3CX-Supply-Chain/potential_compromised_3cxdesktopapp_beaconing_activity_netcon.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where (RemoteUrl contains "akamaicontainer.com" or RemoteUrl contains "akamaitechcloudservices.com" or RemoteUrl contains "azuredeploystore.com" or RemoteUrl contains "azureonlinecloud.com" or RemoteUrl contains "azureonlinestorage.com" or RemoteUrl contains "dunamistrd.com" or RemoteUrl contains "glcloudservice.com" or RemoteUrl contains "journalide.org" or RemoteUrl contains "msedgepackageinfo.com" or RemoteUrl contains "msstorageazure.com" or RemoteUrl contains "msstorageboxes.com" or RemoteUrl contains "officeaddons.com" or RemoteUrl contains "officestoragebox.com" or RemoteUrl contains "pbxcloudeservices.com" or RemoteUrl contains "pbxphonenetwork.com" or RemoteUrl contains "pbxsources.com" or RemoteUrl contains "qwepoi123098.com" or RemoteUrl contains "sbmsa.wiki" or RemoteUrl contains "sourceslabs.com" or RemoteUrl contains "visualstudiofactory.com" or RemoteUrl contains "zacharryblogs.com") and InitiatingProcessFolderPath endswith "\\3CXDesktopApp.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
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
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "RemoteIP"
    }
  }

  entity_mapping {
    entity_type = "URL"
    field_mapping {
      identifier  = "Url"
      column_name = "RemoteUrl"
    }
  }
}