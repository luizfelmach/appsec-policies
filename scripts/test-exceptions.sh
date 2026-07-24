#!/usr/bin/env bash

set -u

failures=0

check() {
  local name="$1"
  local expected="$2"
  local url="$3"
  local actual

  actual=$(curl --silent --show-error --output /dev/null \
    --write-out '%{http_code}' --max-time 20 "$url") || actual="curl-error"

  if [[ "$actual" == "$expected" ]]; then
    printf 'PASS  %-32s expected=%s actual=%s\n' "$name" "$expected" "$actual"
  else
    printf 'FAIL  %-32s expected=%s actual=%s\n' "$name" "$expected" "$actual"
    failures=$((failures + 1))
  fi
}

check_rate_limit() {
  local actual

  for _ in 1 2 3 4; do
    actual=$(curl --silent --show-error --output /dev/null \
      --write-out '%{http_code}' --max-time 20 \
      'http://echo.localtest.me/rate') || actual="curl-error"
  done

  if [[ "$actual" == "403" ]]; then
    printf 'PASS  %-32s expected=%s actual=%s\n' \
      'rate limit: fourth request' 403 "$actual"
  else
    printf 'FAIL  %-32s expected=%s actual=%s\n' \
      'rate limit: fourth request' 403 "$actual"
    failures=$((failures + 1))
  fi
}

xss='%3Cscript%3Ealert%281%29%3C%2Fscript%3E'

check 'baseline: normal request' 200 'http://echo.localtest.me/'
check 'baseline: XSS blocked' 403 "http://echo.localtest.me/?q=$xss"
check 'drop: normal path' 200 'http://echo.localtest.me/drop-control'
check 'drop: /blocked' 403 'http://echo.localtest.me/blocked'
check 'accept: normal path' 200 'http://echo.localtest.me/allowed'
check 'accept: XSS on /allowed' 200 "http://echo.localtest.me/allowed?q=$xss"
check 'accept: XSS outside rule' 403 "http://echo.localtest.me/?q=$xss"
check 'skip: ignored parameter' 200 "http://echo.localtest.me/skip?ignored=$xss"
check 'skip: other parameter' 403 "http://echo.localtest.me/skip?q=$xss"
check 'suppressLog: normal request' 200 'http://echo.localtest.me/quiet'
check_rate_limit

if ((failures > 0)); then
  printf '\n%d test(s) failed.\n' "$failures"
  exit 1
fi

printf '\nAll exception tests passed.\n'
