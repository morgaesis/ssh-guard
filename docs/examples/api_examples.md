# Model Guard API Examples

## Basic Request

```bash
curl -X POST http://localhost:3000/v1/completions \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "What is the capital of France?"
      }
    ]
  }'
```

## Streaming Request

```bash
curl -X POST http://localhost:3000/v1/completions/stream \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Write a story about a dragon"
      }
    ],
    "stream": true
  }'
```

## Add Validation Rule

```bash
curl -X POST http://localhost:3000/v1/validation/rules \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "name": "content_safety",
    "rule_type": "format",
    "parameters": {
      "pattern": "^[a-zA-Z0-9\\s.,!?]+$"
    },
    "severity": "error"
  }'
```

## Get Security Events

```bash
curl "http://localhost:3000/v1/security/events?severity=high&start_time=2026-03-01T00:00:00Z" \
  -H "X-API-Key: your-api-key"
```

## Get Metrics

```bash
curl http://localhost:3000/v1/metrics \
  -H "X-API-Key: your-api-key"
```

## Health Check

```bash
curl http://localhost:3000/health
```

## Python Client Example

```python
import requests

class ModelGuardClient:
    def __init__(self, api_key, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.headers = {
            "Content-Type": "application/json",
            "X-API-Key": api_key
        }

    def create_completion(self, messages, model="auto"):
        response = requests.post(
            f"{self.base_url}/v1/completions",
            headers=self.headers,
            json={
                "model": model,
                "messages": messages
            }
        )
        response.raise_for_status()
        return response.json()

    def stream_completion(self, messages, model="auto"):
        response = requests.post(
            f"{self.base_url}/v1/completions/stream",
            headers=self.headers,
            json={
                "model": model,
                "messages": messages,
                "stream": True
            },
            stream=True
        )
        response.raise_for_status()
        for line in response.iter_lines():
            if line:
                yield json.loads(line.decode())["data"]

# Usage example
client = ModelGuardClient("your-api-key")

# Basic completion
response = client.create_completion([
    {"role": "user", "content": "What is the capital of France?"}
])
print(response["content"])

# Streaming completion
for chunk in client.stream_completion([
    {"role": "user", "content": "Write a story about a dragon"}
]):
    print(chunk["content"], end="", flush=True)
```

## Node.js Client Example

```javascript
const axios = require('axios');

class ModelGuardClient {
    constructor(apiKey, baseUrl = 'http://localhost:3000') {
        this.baseUrl = baseUrl;
        this.headers = {
            'Content-Type': 'application/json',
            'X-API-Key': apiKey
        };
    }

    async createCompletion(messages, model = 'auto') {
        const response = await axios.post(
            `${this.baseUrl}/v1/completions`,
            {
                model,
                messages
            },
            { headers: this.headers }
        );
        return response.data;
    }

    async *streamCompletion(messages, model = 'auto') {
        const response = await axios.post(
            `${this.baseUrl}/v1/completions/stream`,
            {
                model,
                messages,
                stream: true
            },
            {
                headers: this.headers,
                responseType: 'stream'
            }
        );

        for await (const chunk of response.data) {
            const data = JSON.parse(chunk.toString());
            yield data.data;
        }
    }
}

// Usage example
const client = new ModelGuardClient('your-api-key');

// Basic completion
async function basicExample() {
    const response = await client.createCompletion([
        { role: 'user', content: 'What is the capital of France?' }
    ]);
    console.log(response.content);
}

// Streaming completion
async function streamingExample() {
    for await (const chunk of client.streamCompletion([
        { role: 'user', content: 'Write a story about a dragon' }
    ])) {
        process.stdout.write(chunk.content);
    }
}
```