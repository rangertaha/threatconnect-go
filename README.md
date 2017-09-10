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
go test ./pkg
```

```bash
go run main.go groups
```


```bash
go run main.go groups adversaries
```


```bash
go run examples/groups.go
```
