#!/usr/bin/env bats

setup() {
  load helpers
  source_ip="198.51.$((RANDOM % 254 + 1)).$((RANDOM % 254 + 1))"
}

@test "rate limiting blocks fourth request" {
  for _ in 1 2 3; do
    expect 200 --header "X-Forwarded-For: $source_ip" 'http://rate-limit.localtest.me/rate'
  done

  expect 403 --header "X-Forwarded-For: $source_ip" 'http://rate-limit.localtest.me/rate'
}
