storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true

  # Above the largest base64 value the job sends (26,666,668 characters).
  max_json_string_value_length = 33554432
}

api_addr = "http://new-vault:8200"
