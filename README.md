
# [Martian](https://github.com/google/martian) HTTP/S proxies.

[![pipeline status](https://gitlab.com/pismo/martians/badges/master/pipeline.svg)](https://gitlab.com/pismo/martians/commits/master)

## JWT Claims

The `header.JwtClaims` injects a JWT claim in the request as a HTTP header.

Example configuration that injects an `X-Martian` header with the value of the JWT claim `pismo_martian` into requests:

```
{
  "header.JwtClaims": {
    "scope": ["request"],
    "header": "X-Martian",
    "claim": "pismo_martian"
  }
}
```
