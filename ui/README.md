# UI

UI provides an alternative method to interact with the Magistrala system.

## Configuration

The service is configured using the environment variables presented in the following table. Note that any unset variables will be replaced with their default values.

| Variable                | Description                                                             | Default                                  |
| ----------------------- | ----------------------------------------------------------------------- | ---------------------------------------- |
| MG_UI_LOG_LEVEL         | Log level for UI (debug, info, warn, error)                             | debug                                    |
| MG_UI_PORT              | Port where UI service is run                                            | 9095                                     |
| MG_HTTP_ADAPTER_URL     | HTTP adapter URL                                                        | <http://localhost:8008>                  |
| MG_READER_URL           | Reader URL                                                              | <http://localhost:9011>                  |
| MG_THINGS_URL           | Things URL                                                              | <http://localhost:9000>                  |
| MG_USERS_URL            | Users URL                                                               | <http://localhost:9002>                  |
| MG_INVITATIONS_URL      | Invitations URL                                                         | <http://localhost:9020>                  |
| MG_DOMAINS_URL          | Domains URL                                                             | <http://localhost:8189>                  |
| MG_VERIFICATION_TLS     | Verification TLS flag                                                   | false                                    |
| MG_BOOTSTRAP_URL        | Bootstrap URL                                                           | <http://localhost:9013>                  |
| MG_UI_INSTANCE_ID       | Unique identifier for the UI instance                                   | ""                                       |
| MG_UI_HOST_URL          | Base URL for the UI                                                     | <http://localhost:9095>                  |
| MG_UI_CONTENT_TYPE      | Content type for the UI                                                 | application/senml+json                   |
| MG_UI_DB_HOST           | Database host address                                                   | localhost                                |
| MG_UI_DB_PORT           | Database host port                                                      | 5432                                     |
| MG_UI_DB_USER           | Database user                                                           | magistrala-ui                            |
| MG_UI_DB_PASSWORD       | Database password                                                       | magistrala-ui                            |
| MG_UI_DB_NAME           | Name of the database used by UI service                                 | dashboards                               |
| MG_UI_DB_SSL_MODE       | Database connection SSL mode (disable, require, verify-ca, verify-full) | disable                                  |
| MG_UI_DB_SSL_CERT       | Path to the PEM encoded certificate file                                | ""                                       |
| MG_UI_DB_SSL_KEY        | Path to the PEM encoded key file                                        | ""                                       |
| MG_UI_DB_SSL_ROOT_CERT  | Path to the PEM encoded root certificate file                           | ""                                       |
| MG_GOOGLE_CLIENT_ID     | Google client ID                                                        | ""                                       |
| MG_GOOGLE_CLIENT_SECRET | Google client secret                                                    | ""                                       |
| MG_GOOGLE_REDIRECT_URL  | Google redirect URL                                                     | <http://localhost/oauth/callback/google> |
| MG_GOOGLE_STATE         | Google state                                                            | ""                                       |
| MG_UI_HASH_KEY          | Secure cookie encoding key                                              | ""                                       |
| MG_UI_BLOCK_KEY         | Secure cookie encrypting key                                            | ""                                       |
| MG_UI_PATH_PREFIX       | URL path prefix                                                         | ""                                       |

## Deployment

The service itself is distributed as a Docker container. Check the [`UI`](https://github.com/absmach/magistrala-ui/blob/main/docker/docker-compose.yml) service section in docker-compose to see how the service is deployed.

To start the service outside of the container, execute the following shell script (this would require a Postgres instance running):

```bash
# download the latest version of the service
git clone https://github.com/absmach/magistrala-ui

cd magistrala-ui

# compile the service
make ui

# copy binary to bin
make install

# set the environment variables and run the service
MG_UI_LOG_LEVEL=debug \
MG_UI_PORT=9095 \
MG_HTTP_ADAPTER_URL="http://localhost:8008" \
MG_READER_URL="http://localhost:9011" \
MG_THINGS_URL="http://localhost:9000" \
MG_USERS_URL="http://localhost:9002" \
MG_INVITATIONS_URL="http://localhost:9020" \
MG_DOMAINS_URL="http://localhost:8189" \
MG_VERIFICATION_TLS=false \
MG_BOOTSTRAP_URL="http://localhost:9013" \
MG_UI_INSTANCE_ID="" \
MG_UI_HOST_URL="http://localhost:9095" \
MG_UI_CONTENT_TYPE="application/senml+json" \
MG_UI_DB_HOST="localhost" \
MG_UI_DB_PORT=5432 \
MG_UI_DB_USER="magistrala-ui" \
MG_UI_DB_PASSWORD="magistrala-ui" \
MG_UI_DB_NAME="dashboards" \
MG_UI_DB_SSL_MODE="disable" \
MG_UI_DB_SSL_CERT="" \
MG_UI_DB_SSL_KEY="" \
MG_UI_DB_SSL_ROOT_CERT="" \
MG_GOOGLE_CLIENT_ID="" \
MG_GOOGLE_CLIENT_SECRET="" \
MG_GOOGLE_REDIRECT_URL="http://localhost/oauth/callback/google" \
MG_GOOGLE_STATE="" \
MG_UI_HASH_KEY=""\
MG_UI_BLOCK_KEY=""\
MG_UI_PATH_PREFIX=""\
$GOBIN/magistrala-ui
```
