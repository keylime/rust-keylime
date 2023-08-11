#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2023 Keylime Authors

# Build Docker container locally

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [ "$1" = "--help" -o "$1" = "-h" ] ; then
    echo "USAGE: $0 [VERSION] [KEYLIME_DIR] [DOCKER_BUILDX_FLAGS...]" 1>&2
    echo 1>&2
    echo "Examples:" 1>&2
    echo "$0" 1>&2
    echo "$0 15.1.2" 1>&2
    echo "$0 15.1.2 /different/source/folder" 1>&2
    echo "$0 15.1.2 /source/folder --pull --push" 1>&2
    echo "DOCKERFILE_TYPE=fedora $0" 1>&2 
    echo "DOCKERFILE_TYPE=wolfi $0" 1>&2
    echo 1>&2 
    exit 0
fi

VERSION=${1:-latest}
$( cd -- "${SCRIPT_DIR}/../dev/images" &> /dev/null && pwd )
KEYLIME_DIR=${2:-$( cd -- "${SCRIPT_DIR}/../../" &>/dev/null && pwd )}
# TODO: why is shift N not working?
shift
shift
DOCKER_BUILDX_FLAGS=${@:-"--load"}

# overwrite this with one of the following:
# - distroless (default)
# - fedora
# - wolfi
DOCKERFILE_TYPE="${DOCKERFILE_TYPE:-distroless}"

LOG_DIR=${LOG_DIR:-/tmp}
DOCKERFILE="${SCRIPT_DIR}/Dockerfile.${DOCKERFILE_TYPE}"

docker buildx build \
    -f $DOCKERFILE \
    -t keylime_agent:${VERSION}-${DOCKERFILE_TYPE} \
    --progress=plain \
    --platform=linux/amd64 \
    --build-arg VERSION="$VERSION" \
    $DOCKER_BUILDX_FLAGS $KEYLIME_DIR 2>&1 | tee $LOG_DIR/docker-keylime-agent-build.log
docker tag keylime_agent:${VERSION}-${DOCKERFILE_TYPE} keylime_agent:${VERSION}
