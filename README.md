
# [Martian](https://github.com/google/martian) HTTP/S proxies.

[![pipeline status](https://gitlab.com/pismo/martians/badges/master/pipeline.svg)](https://gitlab.com/pismo/martians/commits/master)

## JWT Modifier

The `jwt.Modifier` injects a JWT claim in the request as a HTTP header.

Example configuration that injects an `X-Martian` header with the value of the JWT claim `pismo_martian` into requests:

```
{
  "jwt.Modifier": {
    "scope": ["request"],
    "header": "X-Martian",
    "claim": "pismo_martian"
  }
}
```

## JWT Verifier

The `jwt.Verifier` checks whether a JWT Claim matches a URI resource.

Example configuration that validates if the `customer_id` claim contenat matches a REST resource ID in the URI. For instance, the bellow configuration would match if the URI contains `/customers/10` and the JWT has a Claim `customer_id=10`:

```
{
   "jwt.Verifier": {
     "scope": ["request"],
     "claim": "customer_id" ,
		 "resource": "customers"
   }
 }
 ```
