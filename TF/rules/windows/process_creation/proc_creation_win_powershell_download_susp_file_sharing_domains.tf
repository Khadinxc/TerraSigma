resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_powershell_download_susp_file_sharing_domains" {
  name                       = "proc_creation_win_powershell_download_susp_file_sharing_domains"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE"
  description                = "Detects potentially suspicious file downloads from file sharing domains using PowerShell.exe Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_download_susp_file_sharing_domains.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_download_susp_file_sharing_domains.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".DownloadString(" or ProcessCommandLine contains ".DownloadFile(" or ProcessCommandLine contains "Invoke-WebRequest " or ProcessCommandLine contains "iwr " or ProcessCommandLine contains "wget ") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll"))) and (ProcessCommandLine contains "anonfiles.com" or ProcessCommandLine contains "cdn.discordapp.com" or ProcessCommandLine contains "ddns.net" or ProcessCommandLine contains "dl.dropboxusercontent.com" or ProcessCommandLine contains "ghostbin.co" or ProcessCommandLine contains "glitch.me" or ProcessCommandLine contains "gofile.io" or ProcessCommandLine contains "hastebin.com" or ProcessCommandLine contains "mediafire.com" or ProcessCommandLine contains "mega.nz" or ProcessCommandLine contains "onrender.com" or ProcessCommandLine contains "pages.dev" or ProcessCommandLine contains "paste.ee" or ProcessCommandLine contains "pastebin.com" or ProcessCommandLine contains "pastebin.pl" or ProcessCommandLine contains "pastetext.net" or ProcessCommandLine contains "pixeldrain.com" or ProcessCommandLine contains "privatlab.com" or ProcessCommandLine contains "privatlab.net" or ProcessCommandLine contains "send.exploit.in" or ProcessCommandLine contains "sendspace.com" or ProcessCommandLine contains "storage.googleapis.com" or ProcessCommandLine contains "storjshare.io" or ProcessCommandLine contains "supabase.co" or ProcessCommandLine contains "temp.sh" or ProcessCommandLine contains "transfer.sh" or ProcessCommandLine contains "trycloudflare.com" or ProcessCommandLine contains "ufile.io" or ProcessCommandLine contains "w3spaces.com" or ProcessCommandLine contains "workers.dev")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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