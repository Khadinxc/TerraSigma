resource "azurerm_sentinel_alert_rule_scheduled" "register_new_ifiltre_for_persistence" {
  name                       = "register_new_ifiltre_for_persistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Register New IFiltre For Persistence"
  description                = "Detects when an attacker registers a new IFilter for an extension. Microsoft Windows Search uses filters to extract the content of items for inclusion in a full-text index. You can extend Windows Search to index new or proprietary file types by writing filters to extract the content, and property handlers to extract the properties of files. - Legitimate registration of IFilters by the OS or software"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryKey contains "\\SOFTWARE\\Classes\\CLSID" and RegistryKey contains "\\PersistentAddinsRegistered\\{89BCB740-6119-101A-BCB7-00DD010655AF}") or (RegistryKey contains "\\SOFTWARE\\Classes\\." and RegistryKey contains "\\PersistentHandler")) and (not(((RegistryKey endswith "\\CLSID\\{4F46F75F-199F-4C63-8B7D-86D48FE7970C}*" or RegistryKey endswith "\\CLSID\\{4887767F-7ADC-4983-B576-88FB643D6F79}*" or RegistryKey endswith "\\CLSID\\{D3B41FA1-01E3-49AF-AA25-1D0D824275AE}*" or RegistryKey endswith "\\CLSID\\{72773E1A-B711-4d8d-81FA-B9A43B0650DD}*" or RegistryKey endswith "\\CLSID\\{098f2470-bae0-11cd-b579-08002b30bfeb}*" or RegistryKey endswith "\\CLSID\\{1AA9BF05-9A97-48c1-BA28-D9DCE795E93C}*" or RegistryKey endswith "\\CLSID\\{2e2294a9-50d7-4fe7-a09f-e6492e185884}*" or RegistryKey endswith "\\CLSID\\{34CEAC8D-CBC0-4f77-B7B1-8A60CB6DA0F7}*" or RegistryKey endswith "\\CLSID\\{3B224B11-9363-407e-850F-C9E1FFACD8FB}*" or RegistryKey endswith "\\CLSID\\{3DDEB7A4-8ABF-4D82-B9EE-E1F4552E95BE}*" or RegistryKey endswith "\\CLSID\\{5645C8C1-E277-11CF-8FDA-00AA00A14F93}*" or RegistryKey endswith "\\CLSID\\{5645C8C4-E277-11CF-8FDA-00AA00A14F93}*" or RegistryKey endswith "\\CLSID\\{58A9EBF6-5755-4554-A67E-A2467AD1447B}*" or RegistryKey endswith "\\CLSID\\{5e941d80-bf96-11cd-b579-08002b30bfeb}*" or RegistryKey endswith "\\CLSID\\{698A4FFC-63A3-4E70-8F00-376AD29363FB}*" or RegistryKey endswith "\\CLSID\\{7E9D8D44-6926-426F-AA2B-217A819A5CCE}*" or RegistryKey endswith "\\CLSID\\{8CD34779-9F10-4f9b-ADFB-B3FAEABDAB5A}*" or RegistryKey endswith "\\CLSID\\{9694E38A-E081-46ac-99A0-8743C909ACB6}*" or RegistryKey endswith "\\CLSID\\{98de59a0-d175-11cd-a7bd-00006b827d94}*" or RegistryKey endswith "\\CLSID\\{AA10385A-F5AA-4EFF-B3DF-71B701E25E18}*" or RegistryKey endswith "\\CLSID\\{B4132098-7A03-423D-9463-163CB07C151F}*" or RegistryKey endswith "\\CLSID\\{d044309b-5da6-4633-b085-4ed02522e5a5}*" or RegistryKey endswith "\\CLSID\\{D169C14A-5148-4322-92C8-754FC9D018D8}*" or RegistryKey endswith "\\CLSID\\{DD75716E-B42E-4978-BB60-1497B92E30C4}*" or RegistryKey endswith "\\CLSID\\{E2F83EED-62DE-4A9F-9CD0-A1D40DCD13B6}*" or RegistryKey endswith "\\CLSID\\{E772CEB3-E203-4828-ADF1-765713D981B8}*" or RegistryKey contains "\\CLSID\\{eec97550-47a9-11cf-b952-00aa0051fe20}" or RegistryKey endswith "\\CLSID\\{FB10BD80-A331-4e9e-9EB7-00279903AD99}*") or (InitiatingProcessFolderPath startswith "C:\\Windows\\System32\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}