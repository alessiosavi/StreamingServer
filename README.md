# StreamingServer

A simple video streaming services with authentication using redis

[![License](https://img.shields.io/github/license/alessiosavi/StreamingServer)](https://img.shields.io/github/license/alessiosavi/StreamingServer)
[![Version](https://img.shields.io/github/v/tag/alessiosavi/StreamingServer)](https://img.shields.io/github/v/tag/alessiosavi/StreamingServer)
[![Code size](https://img.shields.io/github/languages/code-size/alessiosavi/StreamingServer)](https://img.shields.io/github/languages/code-size/alessiosavi/StreamingServer)
[![Repo size](https://img.shields.io/github/repo-size/alessiosavi/StreamingServer)](https://img.shields.io/github/repo-size/alessiosavi/StreamingServer)
[![Issue open](https://img.shields.io/github/issues/alessiosavi/StreamingServer)](https://img.shields.io/github/issues/alessiosavi/StreamingServer)
[![Issue closed](https://img.shields.io/github/issues-closed/alessiosavi/StreamingServer)](https://img.shields.io/github/issues-closed/alessiosavi/StreamingServer)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/9c5dc127effe4048b33ed1718190c299)](https://app.codacy.com/manual/alessiosavi/StreamingServer?utm_source=github.com&utm_medium=referral&utm_content=alessiosavi/StreamingServer&utm_campaign=Badge_Grade_Dashboard)
[![Go Report Card](https://goreportcard.com/badge/github.com/alessiosavi/StreamingServer)](https://goreportcard.com/report/github.com/alessiosavi/StreamingServer)
[![GoDoc](https://godoc.org/github.com/alessiosavi/GoGPUtils?status.svg)](https://godoc.org/github.com/alessiosavi/StreamingServer)

## Introduction

This project is developed for have a plug-and-play video streaming server delegated to expose all the films downloaded
from you main computer. With this tool, you can save all of you preterits films, song, videos into your PC. Then, you
can view these media from anywhere using an internet connection.

The server have a basic authentication system. One endpoint is delegated to register a user, another one is delegated
to manage the log-in phase.

Another endpoint is delegated to verify the account, so before that an account is able to stream your resources, you
have to verify that the account is related to someone that you know

## Requirements

- [GoGPUtils](https://github.com/alessiosavi/GoGPUtils/string) Enhance productivity and avoid to reinvent the wheel
  every time that you start a Go project
- [redis](https://github.com/go-redis/redis) Type-safe Redis client for Golang
- [fasthttp](https://github.com/valyala/fasthttp) Fast HTTP package for Go. Tuned for high performance. Zero memory
  allocations in hot paths. Up to 10x faster than net/http
- [logrus](https://github.com/sirupsen/logrus) Structured, pluggable logging for Go.
- [filename](https://github.com/onrik/logrus/) Hooks for logrus logging

## Table Of Contents

- [StreamingServer](#StreamingServer)
    - [Introduction](#introduction)
    - [Requirements](#requirements)
    - [Table Of Contents](#table-of-contents)
    - [Prerequisites](#prerequisites)
    - [Usage](#usage)
    - [In Details](#in-details)
    - [Example response](#example-response)
    - [Contributing](#contributing)
    - [Versioning](#versioning)
    - [Authors](#authors)
    - [License](#license)
    - [Acknowledgments](#acknowledgments)

## Prerequisites

The software is coded in `golang`, into the `go.mod` file are saved the necessary dependencies. In order to download all
the dependencies, you can type the following string from your terminal

```bash
go get -v -u all
```

## Usage

## In Details

```bash
tree
.
├── auth
│   └── authutils.go
├── conf                            // Folder that contains the configuration files 
│   ├── ssl                         // Folder that contains the certificate for the SSL connection
│   │   ├── localhost.crt
│   │   └── localhost.key
│   └── test.json                   // File that contain the configuration related to the tool
├── crypt                           
│   └── basiccrypt.go               // basiccrypt contain the necessary method to encrypt/decrypt data
├── database
│   └── redis
│       └── basicredis.go           // basicredis contain the necessary method to deal with save/load/update data from/to redis
├── datastructures
│   └── datastructures.go           // datastructures contain the necessary datastructure used among all the project
├── docker-compose.yml
├── Dockerfile
├── go.mod
├── go.sum
├── log
├── main.go
├── README.md
└── utils
    ├── common
    │   └── commonutils.go          // commonutils contain a bunch of method used as utils
    └── http
        └── httputils.go            // httputils contain the core method related to the HTTP functionalities
```

## Example response

TODO

## Contributing

- Feel free to open issue in order to __*require new functionality*__;
- Feel free to open issue __*if you discover a bug*__;
- New idea/request/concept are very appreciated!;

## Test

Test are work in progress, is a good first issue for contribute to the project

## Versioning

We use [SemVer](http://semver.org/) for versioning.

## Authors

- **Alessio Savi** - *Initial work & Concept* - [Linkedin](https://www.linkedin.com/in/alessio-savi-2136b2188/)
    - [Github](https://github.com/alessiosavi)

## Contributors

- **Alessio Savi**

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Acknowledgments

Security, in this phase of the development, is not my first concern. Please, fill an issue if you find something that
can be enhanced from a security POV