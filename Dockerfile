FROM golang:1.13-alpine AS build

COPY main.go .

ARG LDFLAGS

RUN GOOS=linux GOARCH=386 go build -ldflags "${LDFLAGS}" -o github-vul

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/github-vul /go/github-vul
ENTRYPOINT ["/go/github-vul"]

ARG NAME
ARG VERSION
ARG COMMIT
ARG BUILD_DATE

LABEL maintainer="Kamil Sindi" repository="https://github.com/jwplayer/github-vul" homepage="https://github.com/jwplayer/github-vul"

LABEL org.label-schema.name="${NAME}" org.label-schema.build-date="${BUILD_DATE}" org.label-schema.vcs-ref="${COMMIT}" org.label-schema.version="${VERSION}" org.label-schema.schema-version="1.0"

LABEL com.github.actions.name="${NAME}" com.github.actions.description="Enable and report on security vulnerability alerts" com.github.actions.icon="github" com.github.actions.color="black"
