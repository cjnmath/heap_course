#! /bin/bash

MDBOOK=`which mdbook`
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

$MDBOOK serve --open $SCRIPT_DIR -n 0.0.0.0
