# UI

UI provides an alternative method to interact with the Magistrala system.

## Configuration

The service is configured using the environment variables presented in the
following table. Note that any unset variables will be replaced with their
default values.

| Variable            | Description                           | Default               |
| ------------------- | ------------------------------------- | --------------------- |
| MG_UI_LOG_LEVEL     | Log level for UI                      | info                  |
| MG_UI_PORT          | Port where UI service is run          | 9095                  |
| MG_HTTP_ADAPTER_URL | HTTP adapter URL                      | http://localhost:8008 |
| MG_READER_URL       | Reader URL                            | http://localhost:9007 |
| MG_THINGS_URL       | Things URL                            | http://localhost:9000 |
| MG_USERS_URL        | Users URL                             | http://localhost:9002 |
| MG_VERIFICATION_TLS | Verification TLS flag                 | false                 |
| MG_BOOTSTRAP_URL    | Bootstrap URL                         | http://localhost:9013 |
| MG_UI_INSTANCE_ID   | Unique identifier for the UI instance |                       |
| MG_UI_HOST_URL      | Base URL for the UI                   | http://localhost:9095 |
