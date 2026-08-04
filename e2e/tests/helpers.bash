expect() {
  local expected="$1"
  shift

  run curl --silent --show-error --output /dev/null \
    --write-out '%{http_code}' --max-time 20 --noproxy '*' "$@"

  [ "$status" -eq 0 ]
  [ "$output" = "$expected" ]
}
