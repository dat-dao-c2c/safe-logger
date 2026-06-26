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

### Handling AWS Credentials

`safe-logger` automatically detects and masks common AWS-related environment variables and keys, supporting both camelCase and snake_case formats.

```typescript
import { safeLog } from '@datdm198x/safe-logger';

// Example with camelCase
const awsConfig = {
  awsAccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  awsSecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  awsRegion: 'us-east-1'
};

// Example with snake_case
const awsEnvConfig = {
  aws_access_key_id: 'AKIAIOSFODNN7EXAMPLE',
  aws_secret_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
};

console.log(safeLog(awsConfig));
console.log(safeLog(awsEnvConfig));
/*
Output:
{
  awsAccessKeyId: '***************IPLE',
  awsSecretAccessKey: '************************************PLEY',
  awsRegion: '*******-1'
}
{
  aws_access_key_id: '***************IPLE',
  aws_secret_access_key: '************************************PLEY'
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

All tests pass, ensuring reliable masking across various scenarios:
- **General Masking:** Validates passwords, emails, CVVs, and nested structures.
- **Edge Cases:** Handles non-string types, `null`, `undefined`, and empty containers safely.
- **Deep Nesting:** Ensures recursive sanitization works for complex objects.
- **AWS & SMTP:** Verifies consistent masking for both camelCase and UPPER_SNAKE_CASE formats.
- **Comprehensive Coverage:** Validates a wide range of PII, API secrets, and sensitive identifiers.

![Tests Passing](https://img.shields.io/badge/tests-passed-brightgreen)

