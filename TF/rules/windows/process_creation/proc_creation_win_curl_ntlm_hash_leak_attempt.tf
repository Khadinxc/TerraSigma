resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_curl_ntlm_hash_leak_attempt" {
  name                       = "proc_creation_win_curl_ntlm_hash_leak_attempt"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "NTLM Hash Leak Via Curl NTLM Authentication"
  description                = <<DESC
    Detects the use of curl with NTLM authentication and empty credentials (-u :), which can be abused to leak the currently logged-in user's NTLMv2 challenge-response to an attacker-controlled server, enabling offline cracking or relay attacks. When no credentials are provided, the Microsoft-shipped curl passes a NULL identity to Windows SSPI, which automatically falls back to the current user's logon session credentials stored in LSASS — without requiring a plaintext password. This behavior is exclusive to the curl binary shipped by Microsoft (available since Windows 10 / Windows Server 2019), which is built with SSPI support.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_curl_ntlm_hash_leak_attempt.yml

    False Positives:
    - Should be very rare as it's not widely known or used, but could occur in legitimate use cases where curl is used with NTLM authentication and empty credentials, such as in certain scripts or automation tasks.
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine matches regex "(?i)\\s(-u|--user)\\s*:" and (FolderPath endswith "\\curl.exe" or ProcessVersionInfoOriginalFileName =~ "curl.exe") and ProcessCommandLine contains "--ntlm"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1187"]
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