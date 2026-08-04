http_status() {
  curl --silent --show-error --output /dev/null \
    --write-out '%{http_code}' --max-time 20 --noproxy '*' "$@"
}
