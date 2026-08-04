#!/usr/bin/env bats

setup() {
  load helpers
}

@test "prevent allows normal traffic" {
  expect 200 'http://prevent.localtest.me/'
}

@test "prevent blocks XSS" {
  expect 403 'http://prevent.localtest.me/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E'
}
