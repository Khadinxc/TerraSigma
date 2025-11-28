resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_lazagne_execution" {
  name                       = "hacktool_lazagne_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - LaZagne Execution"
  description                = "Detects the execution of the LaZagne. A utility used to retrieve multiple types of passwords stored on a local computer. LaZagne has been leveraged multiple times by threat actors in order to dump credentials. - Some false positive is expected from tools with similar command line flags."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine endswith ".exe all" or ProcessCommandLine endswith ".exe browsers" or ProcessCommandLine endswith ".exe chats" or ProcessCommandLine endswith ".exe databases" or ProcessCommandLine endswith ".exe games" or ProcessCommandLine endswith ".exe git" or ProcessCommandLine endswith ".exe mails" or ProcessCommandLine endswith ".exe maven" or ProcessCommandLine endswith ".exe memory" or ProcessCommandLine endswith ".exe multimedia" or ProcessCommandLine endswith ".exe sysadmin" or ProcessCommandLine endswith ".exe unused" or ProcessCommandLine endswith ".exe wifi" or ProcessCommandLine endswith ".exe windows") and (FolderPath contains ":\\PerfLogs\\" or FolderPath contains ":\\ProgramData\\" or FolderPath contains ":\\Temp\\" or FolderPath contains ":\\Tmp\\" or FolderPath contains ":\\Users\\Public\\" or FolderPath contains ":\\Windows\\Temp\\" or FolderPath contains "\\$Recycle.bin" or FolderPath contains "\\AppData\\" or FolderPath contains "\\Desktop\\" or FolderPath contains "\\Downloads\\" or FolderPath contains "\\Favorites\\" or FolderPath contains "\\Links\\" or FolderPath contains "\\Music\\" or FolderPath contains "\\Photos\\" or FolderPath contains "\\Pictures\\" or FolderPath contains "\\Saved Games\\" or FolderPath contains "\\Searches\\" or FolderPath contains "\\Users\\Contacts\\" or FolderPath contains "\\Users\\Default\\" or FolderPath contains "\\Users\\Searches\\" or FolderPath contains "\\Videos\\" or FolderPath contains "\\Windows\\addins\\" or FolderPath contains "\\Windows\\Fonts\\" or FolderPath contains "\\Windows\\IME\\")) or FolderPath endswith "\\lazagne.exe") or ((ProcessCommandLine contains " all " or ProcessCommandLine contains " browsers " or ProcessCommandLine contains " chats " or ProcessCommandLine contains " databases " or ProcessCommandLine contains " games " or ProcessCommandLine contains " mails " or ProcessCommandLine contains " maven " or ProcessCommandLine contains " memory " or ProcessCommandLine contains " multimedia " or ProcessCommandLine contains " php " or ProcessCommandLine contains " svn " or ProcessCommandLine contains " sysadmin " or ProcessCommandLine contains " unused " or ProcessCommandLine contains " wifi ") and (ProcessCommandLine contains "-1Password" or ProcessCommandLine contains "-apachedirectorystudio" or ProcessCommandLine contains "-autologon" or ProcessCommandLine contains "-ChromiumBased" or ProcessCommandLine contains "-coreftp" or ProcessCommandLine contains "-credfiles" or ProcessCommandLine contains "-credman" or ProcessCommandLine contains "-cyberduck" or ProcessCommandLine contains "-dbvis" or ProcessCommandLine contains "-EyeCon" or ProcessCommandLine contains "-filezilla" or ProcessCommandLine contains "-filezillaserver" or ProcessCommandLine contains "-ftpnavigator" or ProcessCommandLine contains "-galconfusion" or ProcessCommandLine contains "-gitforwindows" or ProcessCommandLine contains "-hashdump" or ProcessCommandLine contains "-iisapppool" or ProcessCommandLine contains "-IISCentralCertP" or ProcessCommandLine contains "-kalypsomedia" or ProcessCommandLine contains "-keepass" or ProcessCommandLine contains "-keepassconfig" or ProcessCommandLine contains "-lsa_secrets" or ProcessCommandLine contains "-mavenrepositories" or ProcessCommandLine contains "-memory_dump" or ProcessCommandLine contains "-Mozilla" or ProcessCommandLine contains "-mRemoteNG" or ProcessCommandLine contains "-mscache" or ProcessCommandLine contains "-opensshforwindows" or ProcessCommandLine contains "-openvpn" or ProcessCommandLine contains "-outlook" or ProcessCommandLine contains "-pidgin" or ProcessCommandLine contains "-postgresql" or ProcessCommandLine contains "-psi-im" or ProcessCommandLine contains "-puttycm" or ProcessCommandLine contains "-pypykatz" or ProcessCommandLine contains "-Rclone" or ProcessCommandLine contains "-rdpmanager" or ProcessCommandLine contains "-robomongo" or ProcessCommandLine contains "-roguestale" or ProcessCommandLine contains "-skype" or ProcessCommandLine contains "-SQLDeveloper" or ProcessCommandLine contains "-squirrel" or ProcessCommandLine contains "-tortoise" or ProcessCommandLine contains "-turba" or ProcessCommandLine contains "-UCBrowser" or ProcessCommandLine contains "-unattended" or ProcessCommandLine contains "-vault" or ProcessCommandLine contains "-vaultfiles" or ProcessCommandLine contains "-vnc" or ProcessCommandLine contains "-winscp"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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