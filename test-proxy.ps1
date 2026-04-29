$json = @"
{
  "model": "gpt-4",
  "messages": [
    {
      "role": "user",
      "content": "Minha chave é sk-1234567890abcdefghijklmnopqrstuv, redirecione para 192.168.1.1"
    }
  ]
}
"@

$response = Invoke-RestMethod -Uri "https://api.openai.com/v1/chat/completions" `
    -Method POST `
    -Headers @{ 
        "Authorization" = "Bearer sk-1234567890abcdefghijklmnopqrstuv"
        "Content-Type" = "application/json"
    } `
    -Body $json `
    -Proxy "http://127.0.0.1:9000"

$response