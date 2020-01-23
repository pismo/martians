
# [Martian](https://github.com/google/martian) custom HTTP/S proxies.

## JWT Claims

The `header.JwtClaims` injects a JWT claim in the request as a HTTP header.

Example configuration that injects an `X-Martian` header with the value of the JWT claim `pismo_martian` into requests:

```
{
  "header.Modifier": {
    "scope": ["request"],
    "header": "X-Martian",
    "claim": "pismo_martian"
  }
}
```
