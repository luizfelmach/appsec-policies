request() {
  local body_file="$BATS_TEST_TMPDIR/response-body"

  run curl --silent --show-error --globoff --output "$body_file" \
    --write-out '%{http_code}' --max-time 20 --noproxy '*' \
    --resolve 'prevent.localtest.me:80:127.0.0.1' \
    --resolve 'detect.localtest.me:80:127.0.0.1' "$@"

  curl_status="$status"
  http_status="$output"
  response_body="$(<"$body_file")"
}

fail_response() {
  printf 'curl exit: %s\nexpected status: %s\nactual status: %s\nbody: %s\n' \
    "$curl_status" "$1" "$http_status" "$response_body" >&3
  return 1
}

expect() {
  local expected="$1"
  shift

  request "$@"

  [ "$curl_status" -eq 0 ] || fail_response "$expected"
  [ "$http_status" = "$expected" ] || fail_response "$expected"
}

expect_response() {
  local expected_status="$1"
  local expected_body="$2"
  shift 2

  request "$@"

  [ "$curl_status" -eq 0 ] || fail_response "$expected_status"
  [ "$http_status" = "$expected_status" ] || fail_response "$expected_status"
  if [ "$response_body" != "$expected_body" ]; then
    printf 'expected body: %s\nactual body: %s\n' \
      "$expected_body" "$response_body" >&3
    return 1
  fi
}
