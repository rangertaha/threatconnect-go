# threatconnect-go


# UNDER DEVELOPMENT

   This project is under development and not ready for use. See below for list of supported endpoints. 






Clone project & enter pkg directory for testing

```bash
git clone git@github.com:rangertaha/threatconnect-go.git
cd threatconnect-go/
```



Create a config file in the top level directory for testing

```bash
cat >>threatconnect.yaml<<END
API:
  VERSION: "v2"
  DEFAULT_ORG:
  BASE_URL: "https://sandbox.threatconnect.com/api/"
  ACCESS_ID: "0000000000000000009887"
  SECRET_KEY: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

LOGGING:
  LEVEL: "debug"

END
```



Run tests to view the supported endpoints

```bash
go test
```

The following Group related endpoints are available:

## Owners

The following Owner related endpoints are available:

- [x]  /v2/owners
- [x]  /v2/owners/mine
- [ ]  /v2/owners/mine/members
- [ ]  /v2/owners/metrics
- [ ]  /v2/owners/{id}/metrics

## Groups

The following Group types are available: *adversaries*, 
campaigns
documents
emails
incidents
signatures
threats

- [x]  /v2/groups
- [x]  /v2/groups/{type}
- [x]  /v2/groups/{type}/{id}
- [x]  /v2/groups/{type}/{id}/attributes
- [x]  /v2/groups/{type}/{id}/attributes/{attributeId}
- [ ]  /v2/groups/{type}/{id}/attributes/{attributeId}/securityLabels
- [ ]  /v2/groups/{type}/{id}/attributes/{attributeId}/securityLabels/{securityLabel}
- [ ]  /v2/groups/{type}/{id}/groups
- [ ]  /v2/groups/{type}/{id}/groups/{associatedGroupType}
- [ ]  /v2/groups/{type}/{id}/groups/{associatedGroupType}/{associatedGroupId}
- [ ]  /v2/groups/{type}/{id}/indicators
- [ ]  /v2/groups/{type}/{id}/indicators/{associatedIndicatorType}
- [ ]  /v2/groups/{type}/{id}/indicators/{associatedIndicatorType}/{associatedIndicator}
- [ ]  /v2/groups/{type}/{id}/publish
- [ ]  /v2/groups/{type}/{id}/securityLabels
- [ ]  /v2/groups/{type}/{id}/securityLabels/{securityLabel}
- [ ]  /v2/groups/{type}/{id}/tags
- [ ]  /v2/groups/{type}/{id}/tags/{tagName}
- [ ]  /v2/groups/{type}/{id}/victimAssets
- [ ]  /v2/groups/{type}/{id}/victimAssets/{victimAssetType}
- [ ]  /v2/groups/{type}/{id}/victimAssets/{victimAssetType}/{assetId}
- [ ]  /v2/groups/{type}/{id}/victims
- [ ]  /v2/groups/{type}/{id}/victims/{victimId}

### Adversary Specific Branches
- [x]  /v2/groups/adversaries/{id}/adversaryAssets
- [x]  /v2/groups/adversaries/{id}/adversaryAssets/handles
- [x]  /v2/groups/adversaries/{id}/adversaryAssets/phoneNumbers
- [x]  /v2/groups/adversaries/{id}/adversaryAssets/urls
- [x]  /v2/groups/adversaries/{id}/adversaryAssets/handles/{assetId}
- [x]  /v2/groups/adversaries/{id}/adversaryAssets/phoneNumbers/{assetId}
- [x]  /v2/groups/adversaries/{id}/adversaryAssets/urls/{assetId}

### Document Specific Branches
- [ ]  /v2/groups/documents/{id}/download
- [ ]  /v2/groups/documents/{id}/upload

### Signature Specific Branch
- [ ]  /v2/groups/signatures/{id}/download