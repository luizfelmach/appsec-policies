#!/usr/bin/env bats

setup() {
  load helpers

  base_url='http://prevent.localtest.me'

  xss='<script>alert(document.domain)</script>'
  sql_injection="1' UNION SELECT username,password FROM users-- -"
  command_injection='; cat /etc/passwd; id'
  path_traversal='../../../../etc/passwd'
}

@test "prevent allows a normal GET" {
  expect_response 200 'hello from appsec e2e' "$base_url/"
}

@test "prevent allows a normal path and query" {
  expect_response 200 'hello from appsec e2e' \
    "$base_url/products/search?q=running+shoes&page=2"
}

@test "prevent allows benign punctuation in a query" {
  expect_response 200 'hello from appsec e2e' \
    --get --data-urlencode "message=Alice's order costs \$25 (tax included)." \
    "$base_url/feedback"
}

@test "prevent allows benign HTML in a query" {
  expect_response 200 'hello from appsec e2e' \
    --get --data-urlencode 'content=<p>Hello <strong>team</strong></p>' \
    "$base_url/content"
}

@test "prevent allows a normal form body" {
  expect_response 200 'hello from appsec e2e' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'name=Alice Smith' \
    --data-urlencode 'message=Please ship order 123 tomorrow.' \
    "$base_url/forms"
}

@test "prevent allows a normal JSON body" {
  expect_response 200 'hello from appsec e2e' \
    --header 'Content-Type: application/json' \
    --data '{"name":"Alice","active":true,"roles":["reader"]}' \
    "$base_url/api/users"
}

@test "prevent allows a normal XML body" {
  expect_response 200 'hello from appsec e2e' \
    --header 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?><order><id>123</id><item>book</item></order>' \
    "$base_url/api/orders"
}

@test "prevent allows benign headers" {
  expect_response 200 'hello from appsec e2e' \
    --header 'X-Request-Context: storefront-search' \
    --user-agent 'appsec-e2e/1.0' \
    "$base_url/headers"
}

@test "prevent allows a benign cookie" {
  expect_response 200 'hello from appsec e2e' \
    --cookie 'session=abc123; preference=compact' \
    "$base_url/account"
}

@test "prevent allows valid PUT requests" {
  expect_response 200 'hello from appsec e2e' \
    --request PUT --header 'Content-Type: application/json' \
    --data '{"displayName":"Alice"}' "$base_url/api/users/123"
}

@test "prevent allows valid PATCH requests" {
  expect_response 200 'hello from appsec e2e' \
    --request PATCH --header 'Content-Type: application/json' \
    --data '{"active":false}' "$base_url/api/users/123"
}

@test "prevent allows valid DELETE requests" {
  expect_response 200 'hello from appsec e2e' \
    --request DELETE "$base_url/api/users/123"
}

@test "prevent blocks XSS in a query" {
  expect 403 --get --data-urlencode "q=$xss" "$base_url/search"
}

@test "prevent blocks XSS in a form body" {
  expect 403 --data-urlencode "comment=$xss" "$base_url/comments"
}

@test "prevent blocks XSS in a JSON body" {
  expect 403 --header 'Content-Type: application/json' \
    --data "{\"comment\":\"$xss\"}" "$base_url/api/comments"
}

@test "prevent blocks XSS in a header" {
  expect 403 --header "X-Search-Term: $xss" "$base_url/search"
}

@test "prevent blocks XSS in a cookie" {
  expect 403 --cookie "preference=$xss" "$base_url/account"
}

@test "prevent blocks SQL injection in a query" {
  expect 403 --get --data-urlencode "id=$sql_injection" "$base_url/users"
}

@test "prevent blocks SQL injection in a form body" {
  expect 403 --data-urlencode "id=$sql_injection" "$base_url/users"
}

@test "prevent blocks SQL injection in a JSON body" {
  expect 403 --header 'Content-Type: application/json' \
    --data "{\"id\":\"$sql_injection\"}" "$base_url/api/users"
}

@test "prevent blocks SQL injection in a cookie" {
  expect 403 --cookie "user_id=$sql_injection" "$base_url/account"
}

@test "prevent blocks command injection in a query" {
  expect 403 --get --data-urlencode "host=$command_injection" "$base_url/diagnostics"
}

@test "prevent blocks command injection in a form body" {
  expect 403 --data-urlencode "host=$command_injection" "$base_url/diagnostics"
}

@test "prevent blocks command injection in a JSON body" {
  expect 403 --header 'Content-Type: application/json' \
    --data "{\"host\":\"$command_injection\"}" "$base_url/api/diagnostics"
}

@test "prevent blocks command injection in a header" {
  expect 403 --header "X-Debug-Command: $command_injection" \
    "$base_url/diagnostics"
}

@test "prevent blocks path traversal in a URL path" {
  expect 403 --path-as-is \
    "$base_url/files/%252e%252e%252f%252e%252e%252fetc%252fpasswd"
}

@test "prevent blocks path traversal in a query" {
  expect 403 --get --data-urlencode "file=$path_traversal" "$base_url/files"
}

@test "prevent blocks path traversal in a form body" {
  expect 403 --data-urlencode "file=$path_traversal" "$base_url/files"
}

@test "prevent blocks path traversal in a JSON body" {
  expect 403 --header 'Content-Type: application/json' \
    --data "{\"file\":\"$path_traversal\"}" "$base_url/api/files"
}

@test "prevent blocks an XXE payload" {
  expect 403 --header 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>' \
    "$base_url/api/import"
}

@test "prevent blocks a non-standard HTTP method" {
  expect 403 --request TRACK "$base_url/"
}
