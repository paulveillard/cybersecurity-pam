#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "================================================================================"
if [[ -f "${DIR}/test.env" ]]; then
  echo "Loading test environment data from: ${DIR}/test.env"
  . "${DIR}/test.env"
fi

echo "Checking test environment data..."
if [[ -z "$ITERATIONS" || -z "$IDP_METADATA" || -z "$TRUSTED_SP" ||
      -z "$PAM_AUTHTOK" || -z "$PAM_RHOST" || -z "$PAM_TYPE" ||
      -z "$PAM_USER" ]]; then
  echo "Failed!"
  exit 2
fi
echo "Succeeded."

IDP_METADATA_FILE=$(mktemp)
echo "$IDP_METADATA" | tr -d '\r' > "${IDP_METADATA_FILE}"

echo "--------------------------------------------------------------------------------"
php -v
echo "--------------------------------------------------------------------------------"
RC=0
START=$(date +%s)

for ((i=1; i<=ITERATIONS; i++)); do
  php -c "${DIR}/php.ini" \
      -f "${DIR}/pam-script-saml.php" \
      userid=mail \
      idp="${IDP_METADATA_FILE}" \
      trusted_sp="${TRUSTED_SP}" \
      grace=2147483647 \
      only_from=127.0.0.1,::1
  RC=$?
  if [[ $RC -ne 0 ]]; then
    echo "An error occured in the test, aborting."
    break
  fi
done

END=$(date +%s)
if [[ $RC -eq 0 ]]; then
  echo "Duration for $ITERATIONS iterations: $(( END-START ))s"
fi
echo "================================================================================"

rm -f "${IDP_METADATA_FILE}"

exit $RC
