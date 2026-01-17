#!/bin/sh

if [ -z "$BUILD_SERVICE_PROJECT" ]; then
  echo "BUILD_SERVICE_PROJECT is not set" >&2
  exit 1
fi

exec build-cli --project "$BUILD_SERVICE_PROJECT" make "$@"
