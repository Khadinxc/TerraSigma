resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_file_downloaded_from_file_sharing_website_via_certutil_exe" {
  name                       = "suspicious_file_downloaded_from_file_sharing_website_via_certutil_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE"
  description                = "Detects the execution of certutil with certain flags that allow the utility to download files from file-sharing websites."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "urlcache " or ProcessCommandLine contains "verifyctl ") and (ProcessCommandLine contains ".githubusercontent.com" or ProcessCommandLine contains "anonfiles.com" or ProcessCommandLine contains "cdn.discordapp.com" or ProcessCommandLine contains "ddns.net" or ProcessCommandLine contains "dl.dropboxusercontent.com" or ProcessCommandLine contains "ghostbin.co" or ProcessCommandLine contains "glitch.me" or ProcessCommandLine contains "gofile.io" or ProcessCommandLine contains "hastebin.com" or ProcessCommandLine contains "mediafire.com" or ProcessCommandLine contains "mega.nz" or ProcessCommandLine contains "onrender.com" or ProcessCommandLine contains "pages.dev" or ProcessCommandLine contains "paste.ee" or ProcessCommandLine contains "pastebin.com" or ProcessCommandLine contains "pastebin.pl" or ProcessCommandLine contains "pastetext.net" or ProcessCommandLine contains "privatlab.com" or ProcessCommandLine contains "privatlab.net" or ProcessCommandLine contains "send.exploit.in" or ProcessCommandLine contains "sendspace.com" or ProcessCommandLine contains "storage.googleapis.com" or ProcessCommandLine contains "storjshare.io" or ProcessCommandLine contains "supabase.co" or ProcessCommandLine contains "temp.sh" or ProcessCommandLine contains "transfer.sh" or ProcessCommandLine contains "trycloudflare.com" or ProcessCommandLine contains "ufile.io" or ProcessCommandLine contains "w3spaces.com" or ProcessCommandLine contains "workers.dev") and (FolderPath endswith "\\certutil.exe" or ProcessVersionInfoOriginalFileName =~ "CertUtil.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1027"]
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