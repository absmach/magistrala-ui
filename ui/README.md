# UI

UI provides an alternative method to interact with the mainflux system.

## Configuration

The service is configured using the environment variables presented in the
following table. Note that any unset variables will be replaced with their
default values.

| Variable                      | Description                                         | Default                |
|-------------------------------|-----------------------------------------------------|------------------------|
| MF_UI_LOG_LEVEL               | Log level for UI                                    | info                   |
| MF_UI_CLIENT_TLS              | TLS verification                                    |                        |
| MF_UI_CA_CERTS                | UI certs                                            |                        |
| MF_UI_PORT                    | Port where UI service is run                        | 9090                   |
| MF_UI_REDIRECT_URL            | Redirect URL for the UI                             | http://localhost:9090/ |
| MF_JAEGER_URL                 | Jaeger server URL                                   |                        |
| MF_HTTP_ADAPTER_URL           | HTTP adapter URL                                    | http://localhost:8008  |
| MF_READER_URL                 | Reader URL                                          | http://localhost:9007  |
| MF_THINGS_URL                 | Things URL                                          | http://localhost:9000  |
| MF_USERS_URL                  | Users URL                                           | http://localhost:9002  |
| MF_VERIFICATION_TLS           | Verification TLS flag                               | false                  |
| MF_SDK_BASE_URL               | SDK base URL                                        | http://mainflux-nginx  |
| MF_BOOTSTRAP_URL              | Bootstrap URL                                       | http://localhost:9013  |
| MF_UI_INSTANCE_ID             | Unique identifier for the UI instance               |                        |
| MF_UI_HOST_URL                | Base URL for the UI                                 | http://localhost:9090  |

