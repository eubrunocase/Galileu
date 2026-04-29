@echo off
REM Teste de deteccao de dados sensiveis via proxy
REM Execute com o proxy ativo

echo [TESTE] Enviando prompt com chave de API simulada...

curl -x http://127.0.0.1:9000 ^
  -X POST https://api.openai.com/v1/chat/completions ^
  -H "Content-Type: application/json" ^
  -H "Authorization: Bearer sk-1234567890abcdefghijklmnopqrstuv" ^
  -d "{\"model\": \"gpt-4\", \"messages\": [{\"role\": \"user\", \"content\": \"Minha chave e sk-1234567890abcdefghijklmnopqrstuv\"}]}" ^
  -k 2>nul

echo.
echo [TESTE] Verifique o log no terminal do galileu.exe