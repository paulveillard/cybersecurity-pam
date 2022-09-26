#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for PHP_PATH in /Applications/MAMP/bin/php/php*/bin; do
  echo "********************************************************************************"
  echo "PHP: ${PHP_PATH}"
  PATH="${PHP_PATH}:${PATH}" "${DIR}/test.sh"
done
