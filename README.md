# Apex Security Scanner API

A simple security code scanner API that detects common security vulnerabilities in JavaScript code.

## Features

- Detects dangerous `eval()` usage
- Identifies hardcoded API keys (OpenAI, GitHub, AWS)
- Flags `child_process` usage and command execution
- Returns findings with severity levels and line numbers
- CORS enabled for cross-origin requests

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
npm start
```

For development:
```bash
npm run dev
```

## Environment Variables

- `PORT` - Port to run the server on (default: 3000)

## API Endpoints

### GET /
Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "service": "Apex Security Scanner"
}
```

**Example:**
```bash
curl http://localhost:3000/
```

### POST /
Scan code for security vulnerabilities.

**Request Body:**
```json
{
  "code": "const result = eval(userInput);"
}
```

**Response:**
```json
{
  "findings": [
    {
      "severity": "high",
      "description": "Dangerous use of eval() function detected - can lead to code injection",
      "line": 1
    }
  ]
}
```

**Example:**
```bash
curl -X POST http://localhost:3000/ \
  -H "Content-Type: application/json" \
  -d '{"code": "const api = \"sk-1234567890abcdef1234567890abcdef1234567890\"; eval(userInput);"}'
```

## Security Patterns Detected

| Pattern | Severity | Description |
|---------|----------|-------------|
| `eval()` | High | Code injection vulnerability |
| `sk-*` (40+ chars) | Critical | OpenAI API key |
| `ghp_*` (36 chars) | Critical | GitHub personal access token |
| `AKIA*` (16 chars) | Critical | AWS access key |
| `child_process` | Medium | Process execution module |
| `exec()` | High | Command execution function |
| `spawn()` | Medium | Process spawning function |

## Error Responses

### 400 Bad Request
```json
{
  "error": "Invalid request",
  "message": "Code field is required and must be a string"
}
```

### 404 Not Found
```json
{
  "error": "Not found",
  "message": "Endpoint not found"
}
```

### 500 Internal Server Error
```json
{
  "error": "Internal server error",
  "message": "Something went wrong"
}
```

## Example Usage

**Scanning vulnerable code:**
```bash
curl -X POST http://localhost:3000/ \
  -H "Content-Type: application/json" \
  -d '{
    "code": "const { exec } = require(\"child_process\");\nconst apiKey = \"sk-1234567890abcdef1234567890abcdef1234567890\";\nconst result = eval(userInput);"
  }'
```

**Response:**
```json
{
  "findings": [
    {
      "severity": "medium",
      "description": "Import of child_process module detected",
      "line": 1
    },
    {
      "severity": "critical",
      "description": "Hardcoded OpenAI API key detected",
      "line": 2
    },
    {
      "severity": "high",
      "description": "Dangerous use of eval() function detected - can lead to code injection",
      "line": 3
    }
  ]
}
```

**Scanning clean code:**
```bash
curl -X POST http://localhost:3000/ \
  -H "Content-Type: application/json" \
  -d '{"code": "console.log(\"Hello, world!\");"}'
```

**Response:**
```json
{
  "findings": []
}
```

## Docker

The API runs in a Docker container. The PORT environment variable is automatically provided by the hosting platform.

## License

MIT