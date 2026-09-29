# Safe Logger

A lightweight TypeScript utility to sanitize sensitive information from objects before logging, preventing potential security risks from leaking credentials in logs.

## Features

- Recursive object sanitization.
- Automatic detection of sensitive fields based on keys (passwords, tokens, API keys, credit cards, PII, etc.).
- Configurable masking strategies for different data types.
- Support for registering custom field maskers via `registerFieldMasker`.

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

### Extending Maskers

You can register custom fields to be masked, either using the default `maskToken` behavior or by providing a custom masking function.

```typescript
import { safeLog, registerFieldMasker } from '@datdm198x/safe-logger';

// 1. Register a field using the default masker (maskToken)
registerFieldMasker('internalCode');

// 2. Register a field with a custom masker function
registerFieldMasker('customSecret', (value) => {
    return `[MASKED:${value.substring(0, 3)}...]`;
});

const payload = {
    internalCode: 'ABC-123456789',
    customSecret: '123456789'
};

console.log(safeLog(payload));
/*
Output:
{
  internalCode: '*********6789',
  customSecret: '[MASKED:123...]'
}
*/
```

### Advanced Examples

`safe-logger` handles complex object structures and automatically detects many common sensitive fields.

```typescript
import { safeLog } from '@datdm198x/safe-logger';

// --- Deep Nesting ---
const deepPayload = {
    user: {
        profile: {
            password: 'deepPassword'
        }
    }
};

// --- Cloud & SMTP Edge Cases ---
const cloudPayload = {
    AWS_SECRET_ACCESS_KEY: 'aws-secret-123',
    smtpPassword: 'smtp-password-123'
};

console.log(safeLog(deepPayload));
console.log(safeLog(cloudPayload));
/*
Output:
{ user: { profile: { password: '********' } } }
{ AWS_SECRET_ACCESS_KEY: '**********23', smtpPassword: '********' }
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

## Command Line

The package ships a `safe-log` command for shell scripts and terminals.
The same command is also available under these aliases:
`safe-logger`, `sanity-logger`, `my-logger`, `sanityLogger`, `safeLogger`, `myLogger`.

```bash
npm install -g @datdm198x/safe-logger   # or run without installing: npx @datdm198x/safe-logger ...
```

```bash
# Environment variable by name (the raw value never appears on the command line)
safe-log API_KEY
# API_KEY=****************ijkl

# JSON object / array
safe-log '{"API_KEY": "123456", "user": {"email": "john.doe@gmail.com"}}'
# {"API_KEY":"******","user":{"email":"j******e@gmail.com"}}

# stdin: JSON, or KEY=VALUE lines (env output, .env files)
curl -s https://api.example.com/config | safe-log --pretty
env | safe-log
cat .env | safe-log

# NAME=VALUE
safe-log DB_PASSWORD=hunter2
# DB_PASSWORD=********
```

| Option | Description |
|---|---|
| `-p`, `--pretty` | Pretty-print JSON output |
| `-h`, `--help` | Show help |

Exit codes: `0` success, `1` input error (unset variable, invalid JSON, stdin over 10 MB), `2` usage error.

> **Security:** prefer `safe-log NAME` or stdin over `safe-log NAME=VALUE` / inline JSON containing
> real secrets — command-line arguments are recorded in shell history and visible in `ps`.
> Masking is key-based: lines that are not `KEY=VALUE` (and JSON values under non-sensitive keys)
> are printed unchanged.

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
- **Custom Maskers:** Verifies the registration and application of custom field maskers.
- **Edge Cases:** Handles non-string types, `null`, `undefined`, and empty containers safely.
- **Deep Nesting:** Ensures recursive sanitization works for complex objects.
- **AWS & SMTP:** Verifies consistent masking for both camelCase and UPPER_SNAKE_CASE formats.
- **Comprehensive Coverage:** Validates a wide range of PII, API secrets, and sensitive identifiers.

![Tests Passing](https://img.shields.io/badge/tests-passed-brightgreen)

