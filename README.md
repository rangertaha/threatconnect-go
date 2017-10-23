### threatconnect-go


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

```bash
go test

INFO[0000] CREATE   /v2/groups/adversaries              
INFO[0000] UPDATE   /v2/groups/adversaries/3031358      
INFO[0000] RETRIEVE /v2/groups/adversaries/3031358      
INFO[0000] DELETE   /v2/groups/adversaries/3031358      
INFO[0001] CREATE   /v2/groups/adversaries/3031360/attributes 
INFO[0001] DELETE   /v2/groups/adversaries/3031360/attributes/0 
INFO[0001] DELETE   /v2/groups/adversaries/3031360      
INFO[0001] CREATE   /v2/groups/adversaries/3031361/adversaryAssets/phoneNumbers 
INFO[0001] RETRIEVE /v2/groups/adversaries/3031361/adversaryAssets/phoneNumbers 
INFO[0001] UPDATE   /v2/groups/adversaries/3031361/adversaryAssets/phoneNumbers/7451 
INFO[0002] RETRIEVE /v2/groups/adversaries/3031361/adversaryAssets/phoneNumbers/7451 
INFO[0002] RETRIEVE /v2/groups/adversaries/3031361/adversaryAssets 
INFO[0002] DELETE   /v2/groups/adversaries/3031361/adversaryAssets/phoneNumbers/7451 
INFO[0002] DELETE   /v2/groups/adversaries/3031361      
INFO[0002] CREATE   /v2/groups/adversaries/3031363/adversaryAssets/urls 
INFO[0003] RETRIEVE /v2/groups/adversaries/3031363/adversaryAssets/urls 
INFO[0003] UPDATE   /v2/groups/adversaries/3031363/adversaryAssets/urls/7452 
INFO[0003] RETRIEVE /v2/groups/adversaries/3031363/adversaryAssets/urls/7452 
INFO[0003] DELETE   /v2/groups/adversaries/3031363/adversaryAssets/urls/7452 
INFO[0003] DELETE   /v2/groups/adversaries/3031363      
INFO[0004] CREATE   /v2/groups/adversaries/3031366/adversaryAssets/handles 
INFO[0004] RETRIEVE /v2/groups/adversaries/3031366/adversaryAssets/handles 
INFO[0004] UPDATE   /v2/groups/adversaries/3031366/adversaryAssets/handles/7453 
INFO[0004] RETRIEVE /v2/groups/adversaries/3031366/adversaryAssets/handles/7453 
INFO[0004] DELETE   /v2/groups/adversaries/3031366/adversaryAssets/handles/7453 
INFO[0005] DELETE   /v2/groups/adversaries/3031366      
INFO[0005] RETRIEVE /v2/types/associationTypes          
INFO[0005] CREATE   /v2/groups/campaigns                
INFO[0005] UPDATE   /v2/groups/campaigns/3031368        
INFO[0005] RETRIEVE /v2/groups/campaigns/3031368        
INFO[0005] DELETE   /v2/groups/campaigns/3031368        
INFO[0006] CREATE   /v2/groups/documents                
INFO[0006] UPDATE   /v2/groups/documents/3031369        
INFO[0006] RETRIEVE /v2/groups/documents/3031369        
INFO[0006] DELETE   /v2/groups/documents/3031369        
INFO[0006] CREATE   /v2/groups/emails                   
INFO[0006] UPDATE   /v2/groups/emails/3031371           
INFO[0007] RETRIEVE /v2/groups/emails/3031371           
INFO[0007] DELETE   /v2/groups/emails/3031371           
INFO[0007] RETRIEVE /v2/groups                          
INFO[0007] CREATE   /v2/groups/incidents                
INFO[0007] UPDATE   /v2/groups/incidents/3031372        
INFO[0007] RETRIEVE /v2/groups/incidents/3031372        
INFO[0007] DELETE   /v2/groups/incidents/3031372        
INFO[0008] RETRIEVE /v2/owners                          
INFO[0008] RETRIEVE /v2/owners/mine                     
INFO[0008] RETRIEVE /v2/owners/445                      
INFO[0008] CREATE   /v2/groups/signatures               
INFO[0008] UPDATE   /v2/groups/signatures/3031373       
INFO[0008] RETRIEVE /v2/groups/signatures/3031373       
INFO[0009] DELETE   /v2/groups/signatures/3031373       
INFO[0009] CREATE   /v2/groups/threats                  
INFO[0009] UPDATE   /v2/groups/threats/3031374          
INFO[0009] RETRIEVE /v2/groups/threats/3031374          
INFO[0009] DELETE   /v2/groups/threats/3031374          
INFO[0009] RETRIEVE /v2/whoami 
```

