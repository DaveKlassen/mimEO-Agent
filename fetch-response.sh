#!/bin/sh

if [ -z "$HOST_PORT" ]; then
  echo "Please set the HOST_PORT environment variable that you are using"
  echo 'export HOST_PORT="10.0.0.149:8083"'
  exit
fi

if [ -z "$BEARER_TOKEN" ]; then
  echo "Please set the BEARER_TOKEN environment variable that you are using"
  echo 'export BEARER_TOKEN="ABCD"'
  exit
fi

if [ -z "$MODEL" ]; then
  MODEL="smollm-360m"
fi


msg="Hello"
if [ ! -z "$1" ]; then
  msg="$1"
else
  echo "Please enter some input in quotes to query the AI" 
  echo 'Ex. ./fetch-response.sh "Who am I and what am I doing?"'
  exit
fi

echo '{
    "model": "'$MODEL'",
    "messages": [{"role": "user", "content": "'$msg'"}],
    "stream": true
  }' > input.txt

echo "You are asking the model: $MODEL "
echo "\t\t\t $msg"
echo "Thinking on this..."
curl -o out.txt http://$HOST_PORT/mimik-ai/openai/v1/chat/completions -H "Content-Type: application/json" -H "Authorization: Bearer $BEARER_TOKEN" -d @input.txt  > /dev/null 2>&1
cat out.txt | sed -e 's/data: {\"id\":/,{\"id\":/g' > out1.txt
cat out1.txt | sed -e '1s/^,/[\n/g' > out2.txt
cat out2.txt | sed -e 's/data: \[DONE//g' > out.json
cat out.json | jq -r '.[] | .choices[].delta.content' > c.txt 
cat c.txt | sed -e '1s/^null//g' > c1.txt
cat c1.txt | sed -e '$s/^null//g' > c2.txt
cat c2.txt | tr -d '\n' > response.txt

echo "\t\t\t... The answer from $MODEL is:"
cat response.txt
