#!/usr/bin/env bash
# Usage: ./test_register.sh <identifier> <password>
# Beispiel: ./test_register.sh user@example.com MeinPass!2025

ID = "${1:-user$(date +%s)@example.com}"
PW = "${2:-MeinPass!2025}"

echo "=== TEST REGISTER SCRIPT ==="
echo "Identifier: $ID"
echo "Password: $PW"
echo ""

# ---------- 1) Request code ----------
echo "1) Requesting verification code..."
RESP = $(curl -s -X POST -H "Content-Type: application/json" -d "{\"identifier\":\"$ID\"}" http://localhost:3000/api/request-code)
echo "Response: $RESP"

# ---------- 2) Extract debugCode ----------
CODE=$(echo "$RESP" | sed -n 's/.*"debugCode":"\([0-9]*\)".*/\1/p')
if [ -z "$CODE" ]; 
  then
  echo "Kein debugCode gefunden! Prüfe Server-Logs."
  exit 2
fi
echo "Got debugCode: $CODE"
echo ""

# ---------- 3) Verify & set ----------
echo "2) Verifying and setting password..."
RESP2 = $(curl -s -X POST -H "Content-Type: application/json" \
  -d "{\"identifier\":\"$ID\",\"code\":\"$CODE\",\"password\":\"$PW\",\"purpose\":\"register\"}" \
  http://localhost:3000/api/verify-and-set)
echo "Response: $RESP2"
echo ""

# ---------- 4) Show DB users & todos ----------
echo "=== DB Users ==="
sqlite3 db/database.sqlite "SELECT id, identifier, verified, CASE WHEN password_hash IS NULL THEN 0 ELSE 1 END as has_pw FROM users;"

echo ""
echo "=== DB Todos ==="
sqlite3 db/database.sqlite "SELECT id, text, done, owner_id FROM todos ORDER BY id;"
echo ""
