#!/usr/bin/env bats

setup() {
  load helpers

  base_url='http://detect.localtest.me'
  expected_body='hello from appsec e2e'

  xss='<script>alert(document.domain)</script>'
  sql_injection="1' UNION SELECT username,password FROM users-- -"
  command_injection='; cat /etc/passwd; id'
  path_traversal='../../../../etc/passwd'
}

@test "detect allows a normal GET" {
  expect_response 200 "$expected_body" "$base_url/"
}

@test "detect allows a normal path and query" {
  expect_response 200 "$expected_body" \
    "$base_url/products/search?q=running+shoes&page=2"
}

@test "detect allows benign punctuation in a query" {
  expect_response 200 "$expected_body" \
    --get --data-urlencode "message=Alice's order costs \$25 (tax included)." \
    "$base_url/feedback"
}

@test "detect allows benign HTML in a query" {
  expect_response 200 "$expected_body" \
    --get --data-urlencode 'content=<p>Hello <strong>team</strong></p>' \
    "$base_url/content"
}

@test "detect allows a normal form body" {
  expect_response 200 "$expected_body" \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'name=Alice Smith' \
    --data-urlencode 'message=Please ship order 123 tomorrow.' \
    "$base_url/forms"
}

@test "detect allows a normal JSON body" {
  expect_response 200 "$expected_body" \
    --header 'Content-Type: application/json' \
    --data '{"name":"Alice","active":true,"roles":["reader"]}' \
    "$base_url/api/users"
}

@test "detect allows a normal XML body" {
  expect_response 200 "$expected_body" \
    --header 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?><order><id>123</id><item>book</item></order>' \
    "$base_url/api/orders"
}

@test "detect allows benign headers" {
  expect_response 200 "$expected_body" \
    --header 'X-Request-Context: storefront-search' \
    --user-agent 'appsec-e2e/1.0' \
    "$base_url/headers"
}

@test "detect allows a benign cookie" {
  expect_response 200 "$expected_body" \
    --cookie 'session=abc123; preference=compact' \
    "$base_url/account"
}

@test "detect allows valid PUT requests" {
  expect_response 200 "$expected_body" \
    --request PUT --header 'Content-Type: application/json' \
    --data '{"displayName":"Alice"}' "$base_url/api/users/123"
}

@test "detect allows valid PATCH requests" {
  expect_response 200 "$expected_body" \
    --request PATCH --header 'Content-Type: application/json' \
    --data '{"active":false}' "$base_url/api/users/123"
}

@test "detect allows valid DELETE requests" {
  expect_response 200 "$expected_body" \
    --request DELETE "$base_url/api/users/123"
}

@test "detect allows XSS in a query" {
  expect_response 200 "$expected_body" \
    --get --data-urlencode "q=$xss" "$base_url/search"
}

@test "detect allows XSS in a form body" {
  expect_response 200 "$expected_body" \
    --data-urlencode "comment=$xss" "$base_url/comments"
}

@test "detect allows XSS in a JSON body" {
  expect_response 200 "$expected_body" \
    --header 'Content-Type: application/json' \
    --data "{\"comment\":\"$xss\"}" "$base_url/api/comments"
}

@test "detect allows XSS in a header" {
  expect_response 200 "$expected_body" \
    --header "X-Search-Term: $xss" "$base_url/search"
}

@test "detect allows XSS in a cookie" {
  expect_response 200 "$expected_body" \
    --cookie "preference=$xss" "$base_url/account"
}

@test "detect allows SQL injection in a query" {
  expect_response 200 "$expected_body" \
    --get --data-urlencode "id=$sql_injection" "$base_url/users"
}

@test "detect allows SQL injection in a form body" {
  expect_response 200 "$expected_body" \
    --data-urlencode "id=$sql_injection" "$base_url/users"
}

@test "detect allows SQL injection in a JSON body" {
  expect_response 200 "$expected_body" \
    --header 'Content-Type: application/json' \
    --data "{\"id\":\"$sql_injection\"}" "$base_url/api/users"
}

@test "detect allows SQL injection in a cookie" {
  expect_response 200 "$expected_body" \
    --cookie "user_id=$sql_injection" "$base_url/account"
}

@test "detect allows command injection in a query" {
  expect_response 200 "$expected_body" \
    --get --data-urlencode "host=$command_injection" "$base_url/diagnostics"
}

@test "detect allows command injection in a form body" {
  expect_response 200 "$expected_body" \
    --data-urlencode "host=$command_injection" "$base_url/diagnostics"
}

@test "detect allows command injection in a JSON body" {
  expect_response 200 "$expected_body" \
    --header 'Content-Type: application/json' \
    --data "{\"host\":\"$command_injection\"}" "$base_url/api/diagnostics"
}

@test "detect allows command injection in a header" {
  expect_response 200 "$expected_body" \
    --header "X-Debug-Command: $command_injection" "$base_url/diagnostics"
}

@test "detect allows path traversal in a URL path" {
  expect_response 200 "$expected_body" --path-as-is \
    "$base_url/files/%252e%252e%252f%252e%252e%252fetc%252fpasswd"
}

@test "detect allows path traversal in a query" {
  expect_response 200 "$expected_body" \
    --get --data-urlencode "file=$path_traversal" "$base_url/files"
}

@test "detect allows path traversal in a form body" {
  expect_response 200 "$expected_body" \
    --data-urlencode "file=$path_traversal" "$base_url/files"
}

@test "detect allows path traversal in a JSON body" {
  expect_response 200 "$expected_body" \
    --header 'Content-Type: application/json' \
    --data "{\"file\":\"$path_traversal\"}" "$base_url/api/files"
}

@test "detect allows an XXE payload" {
  expect_response 200 "$expected_body" \
    --header 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>' \
    "$base_url/api/import"
}

@test "detect allows a non-standard HTTP method" {
  expect_response 200 "$expected_body" --request TRACK "$base_url/"
}
