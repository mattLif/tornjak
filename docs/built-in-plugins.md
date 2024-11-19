# Built-In Plugins

-  [Server plugin: Authentication "Keycloak"](#server-plugin-authentication-keycloak)
-  [Server plugin: Authorization "RBAC"](#server-plugin-authorization-rbac)
-  [Server plugin: Datastore "SQL"](#server-plugin-datastore-sql)
-  [Server plugin: SPIRECRDManager](#server-plugin-spirecrdmanager)

## Server plugin: Authentication "Keycloak"

Please see our documentation on the [authorization feature](./user-management.md) for more complete details.

Note that simply enabling this feature will NOT enable authorization. In order to apply authorization logic to user details, one must also enable an Authorization plugin. Any output from this layer, including authentication errors, are to be interpreted by an Authorization layer.

The configuration has the following key-value pairs:

| Key         | Description                                                             | Required            |
| ----------- | ----------------------------------------------------------------------- | ------------------- |
| issuer      | Issuer URL for OIDC Discovery with external IAM System                  | True                |
| audience    | Expected audience value in received JWT tokens                          | False (Recommended) |

A sample configuration file for syntactic referense is below:

```hcl
    Authenticator "Keycloak" {
        plugin_data {
            issuer = "http://host.docker.internal:8080/realms/tornjak"
            audience = "tornjak-backend"
        }
    }
```

NOTE: If audience field is missing or empty, the server will log a warning and NOT perform an audience check.
It is highly recommended `audience` is populated to ensure only tokens meant for the Tornjak Backend are accepted.

### User Info extracted

This plugin assumes roles are available in `realm_access.roles` in the JWT and passes this list as user.roles.

These mapped values are passed to the authorization layer.

## Server plugin: Authorization "RBAC"

Please see our documentation on the [authorization feature](./user-management.md) for more complete details.

This configuration has the following inputs:

| Key | Description | Required |
| --- | ----------- | -------- |
| name | name of the policy for logging purposes | no |
| `role "<x>" {desc = "<y>"}` | `<x>` is the name of a role that can be allowed access; `<y>` is a short description | no |
| `API "<x>" {allowed_roles = ["<z1>", ...]}` | `<x>` is the name of the API that will allow access to roles listed such as `<z1>` | no |

There can (and likely will be) multiple `role` and `API` blocks. If there are no role blocks, no API will be allowed any access. If there is a missing API block, no access will be granted for that API.

A sample configuration file for syntactic referense is below:

```hcl
Authorizer "RBAC" {
  plugin_data {
    name = "Admin Viewer Policy"
    role "admin" { desc = "admin person" }
    role "viewer" { desc = "viewer person" }
    role "" { desc = "authenticated person" }

    API "/" { allowed_roles = [""] }
    API "/api/healthcheck" { allowed_roles = ["admin", "viewer"] }
    API "/api/debugserver" { allowed_roles = ["admin", "viewer"] }
    API "/api/agent/list" { allowed_roles = ["admin", "viewer"] }
    API "/api/entry/list" { allowed_roles = ["admin", "viewer"] }
    API "/api/tornjak/serverinfo" { allowed_roles = ["admin", "viewer"] }
    API "/api/tornjak/selectors/list" { allowed_roles = ["admin", "viewer"] }
    API "/api/tornjak/agents/list" { allowed_roles = ["admin", "viewer"] }
    API "/api/tornjak/clusters/list" { allowed_roles = ["admin", "viewer"] }
    API "/api/agent/ban" { allowed_roles = ["admin"] }
    API "/api/agent/delete" { allowed_roles = ["admin"] }
    API "/api/agent/createjointoken" { allowed_roles = ["admin"] }
    API "/api/entry/create" { allowed_roles = ["admin"] }
    API "/api/entry/delete" { allowed_roles = ["admin"] }
    API "/api/tornjak/selectors/register" { allowed_roles = ["admin"] }
    API "/api/tornjak/clusters/create" { allowed_roles = ["admin"] }
    API "/api/tornjak/clusters/edit" { allowed_roles = ["admin"] }
    API "/api/tornjak/clusters/delete" { allowed_roles = ["admin"] }
  }
}
```

NOTE: If this feature is enabled without an authentication layer, it will render all calls uncallable.

The above specification assumes roles `admin` and `viewer` are passed by the authentication layer. In this example, the following apply:

1. If user has `admin` role, can perform any call
2. If user has `viewer` role, can perform all read-only calls (See lists below)
3. If user is authenticated with no role, can perform only `/` Tornjak home call.

### Valid inputs

There are a couple failure cases in which the plugin will fail to initialize and the Tornjak backend will not run:

1. If an included API block has an undefined API (`API "<x>" {...}` where `x` is not a Tornjak API)
2. If an included API block has an undefined role (There exists `API "<x>" {allowed_roles = [..., "<y>", ...]}` such that for all `role "<z>" {...}`, `y != z`)

### The empty string role ""

If there is a role listed with name `""`, this enables some APIs to allow all users where the authentication layer does not return error. In the above example, only the `/` API has this behavior.

### Additional behavior specification

If there is a role that is not included as an `allowed_role` in any API block, a user will not be granted access to any API based on that role.

## Server plugin: Datastore "SQL"

Note the Datastore is a required plugin, and currently, as the SQL datastore is the only supported instance of the datastore plugin, there must be a section configuring this upon Tornjak backend startup.

The configuration has the following key-value pairs:

| Key         | Description                  | Required            |
| ----------- | ---------------------------- | ------------------- |
| drivername  | Driver for SQL database      | True                |
| filename    | Location of database         | True                |

A sample configuration file for syntactic reference is below:

```hcl
    DataStore "sql" {
        plugin_data {
            issuer = "sqlite3"
            audience = "/run/spire/data/tornjak.sqlite3"
        }
    }
```

## Server plugin: SPIRECRDManager

Note the SPIRECRDManager is an optional plugin. This plugin enables the creation of SPIRE CRDs on the cluster Tornjak is deployed on. It enables the following API calls:

- `GET /api/v1/spire-controller-manager/clusterfederatedtrustdomains`

> [!IMPORTANT]
> This plugin requires two things: (a) That Tornjak is deployed in the same cluster as the relevant CRDs as it uses its own service account token to talk to the kube API server. (b) That the proper permissions are given to the Service Account token that Tornjak will use. Current Helm charts deploy SPIRE Controller manager and Tornjak in the same pod as the SPIRE server, so no extra configuration is necessary if deployed this way.

The configuration has the following key-value pairs:

| Key        | Description                      | Required            |
| ---------- | -------------------------------- | ------------------- |
| classname  | className label for created CRDs | False               |

A sample configuration file for syntactic reference is below:

```hcl
    SPIREControllerManager {
        plugin_data {
            classname = "spire-mgmt-spire"
        }
    }
```
