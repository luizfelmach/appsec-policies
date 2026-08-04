#!/usr/bin/env bats

setup() {
  load helpers
}

@test "prevent allows normal traffic" {
  run http_status 'http://prevent.localtest.me/'

  [ "$status" -eq 0 ]
  [ "$output" = '200' ]
}

@test "prevent blocks XSS" {
  run http_status 'http://prevent.localtest.me/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E'

  [ "$status" -eq 0 ]
  [ "$output" = '403' ]
}
