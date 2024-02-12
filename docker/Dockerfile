# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.22-alpine AS builder
ARG SVC
ARG GOARCH
ARG GOARM
ARG VERSION
ARG COMMIT
ARG TIME

WORKDIR /app

COPY . .

#Build
RUN apk update \
    && apk add make\
    && make $SVC \
    && mv build/$SVC /exe

FROM scratch
COPY --from=builder /exe /
COPY --from=builder /app/ui/web /ui/web
ENTRYPOINT ["/exe"]
