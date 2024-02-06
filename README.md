# Magistrala-ui

[![Create and publish a Docker image](https://github.com/absmach/magistrala-ui/actions/workflows/build.yml/badge.svg)](https://github.com/absmach/magistrala-ui/actions/workflows/build.yml) [![Continuous Integration](https://github.com/absmach/magistrala-ui/actions/workflows/ci.yaml/badge.svg)](https://github.com/absmach/magistrala-ui/actions/workflows/ci.yaml) [![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

The Magistrala-ui functions as a Graphical User Interface (GUI) designed to interact with Magistrala services, encompassing both the creation and management aspects of users, things, channels, and groups. It streamlines tasks such as user and thing creation, channel establishment, policy configuration, and HTTP message transmission across various channels.

Magistrala-ui can be obtained as an independent subset of Magistrala; however, it requires integration with the Magistrala core services to function properly.

## Prerequisites

To run Magistrala-ui, you need the following components:

- [Magistrala](https://github.com/absmach/magistrala) (latest version)
- [Go](https://golang.org/doc/install) (version 1.19.2)
- [Docker-compose](https://docs.docker.com/compose/install/) (latest version)
- [make](https://www.gnu.org/software/make/manual/make.html)

## Installation

After installing the prerequisites, execute the following commands from the project's root directory:

```bash
make
```

```bash
make run
```

These commands will launch Magistrala-ui. To use the Magistrala-ui, ensure that the Magistrala core services are operational. You can achieve this by installing [Magistrala](https://github.com/absmach/magistrala) and its prerequisites.

To build the docker images for the ui service, run the following commands which will build the docker images in different configurations.

This command will build the docker images for the ui service in default configuration.

```bash
make docker
```

This will build the development docker images for ui.

```bash
make docker_dev
```

You can also run ui via docker using the following command.

```bash
make run_docker
```

This brings up the docker images and runs ui in the configuration specified in the .env file.

## Usage

Once both Magistrala core and Magistrala-ui are running, you can access the Magistrala-ui interface locally by entering the address: [http://localhost:9095](http://localhost:9095).

On the login page, use the provided credentials to log in to the interface:

```conf
Email: admin@example.com
Password: 12345678
```

Upon logging in, you will be directed to the Dashboard, which provides an overview of the Magistrala user interface. The sidebar elements, such as Users/Groups, allow you to navigate to specific pages for performing actions related to Users, Groups, Things, Channels, and Bootstraps.

### Users

You can create individual users or upload a CSV file to add multiple users. When creating a user, input the User Identity, User Secret, Tags (as a string slice), and Metadata (in JSON format). The User Identity should be unique and can be an email. The User Secret serves as a password for user login. Metadata provides additional user information.

When using a CSV file to create multiple users, the file should contain user names in one column and their respective credentials in subsequent columns. In the CSV file, the credentials should also follow in the order of email and then password.

### Groups

Similar to users, you can create single or multiple groups by uploading a CSV file. For group creation, provide the Group Name (required), Description, Parent ID, and Metadata (in JSON format).

When using a CSV file to create multiple groups, the file should contain group names in one column and corresponding Parent IDs in subsequent columns.

For more details, refer to the official [Documentation](http://docs.mainflux.io/cli/#things-management).

### Things

You can create individual things or upload a CSV file for multiple things. When adding a thing, provide the Thing Name (required), Thing ID, Identity, Secret, Tags (as a string slice), and Metadata (in JSON format). The Thing Secret should be unique and is used to identify the thing. Metadata offers additional information about the thing.

For multiple things, use a CSV file with thing names in one column. Refer to the official [Documentation](http://docs.mainflux.io/cli/#things-management) for CSV file details.

### Channels

Similarly, you can add individual or multiple channels using a CSV file. For channel creation, enter the Channel Name (required), select the Parent ID, provide a Description, and include Metadata (in JSON format).

### Bootstrap

To use bootstrap, ensure that the [bootstrap](http://docs.mainflux.io/bootstrap/) addon is active as part of the Magistrala core services.

To configure bootstrap, provide the Name, Thing ID, External ID, External Key, Channel (as a string slice), Content (in JSON format), Client Cert, Client Key, and CA Cert.

## Dev Guide

UI code is formatted using [prettier](https://prettier.io/). To install prettier, check the [installation guide](https://github.com/NiklasPor/prettier-plugin-go-template). Node.js and npm are required to install prettier.

Install prettier and prettier-plugin-go-template using the following command:

```bash
 npm install -g prettier prettier-plugin-go-template
```

To format the code, run the following command:

```bash
prettier --write .
```
