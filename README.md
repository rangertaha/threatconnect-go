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

