#!/bin/sh
set -eu
exec dotnet "OpenEtradeMcp.${SERVICE}.dll" "$@"
