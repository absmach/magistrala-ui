# Docker Composition

Configure environment variables and run Magistrala UI Docker Composition.

\*Note\*\*: `docker-compose` uses `.env` file to set all environment variables. Ensure that you run the command from the same location as .env file.

## Installation

Follow the [official documentation](https://docs.docker.com/compose/install/).

## Usage

Run following commands from project root directory.

1. To run the docker-compose

```
docker-compose -f docker/docker-compose.yml --env-file docker/.env up
```

2. to stop docker-compose

```
docker-compose -f docker/docker-compose.yml --env-file docker/.env down -v
```
