# Safe Logger

A lightweight TypeScript utility to sanitize sensitive information from objects before logging, preventing potential security risks from leaking credentials in logs.

## Features

- Recursive object sanitization.
- Automatic detection of sensitive fields based on keys (passwords, tokens, API keys, credit cards, PII, etc.).
- Configurable masking strategies for different data types.

## Installation

```bash
npm install @datdm198x/safe-logger
```

## Usage

```typescript
import { safeLog } from '@datdm198x/safe-logger';

const sensitiveData = {
  username: 'john_doe',
  password: 'my-super-secret-password',
  api_key: 'sk_live_1234567890abcdef',
  email: 'john.doe@gmail.com'
};

const sanitizedData = safeLog(sensitiveData);
console.log(sanitizedData);
/*
Output:
{
  username: 'john_doe',
  password: '********',
  api_key: '********cdef',
  email: 'j******e@gmail.com'
}
*/
```

## Development

### Build
```bash
npm run build
```

### Testing
```bash
npm test
```
