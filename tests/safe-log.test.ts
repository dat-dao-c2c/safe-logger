import { describe, it, expect } from 'vitest';
import { safeLog, registerFieldMasker } from '../src/index.js';

describe('safeLog', () => {
  it('should mask sensitive fields as expected', () => {
    const payload = {
      username: 'john',
      password: 'SuperSecret',
      JWT: 'eyJhbGc123456789ABCDEFG',
      accessToken: 'ABCDEFG123456789',
      ACCESS_TOKEN: 'ABCDEFG123456789',
      access_token: 'ABCDEFG123456789',
      githubAccessToken: 'ghp_1234567890',
      stripe_api_key: 'sk_test_xxxxx',
      client_secret: 'abcdef',
      Authorization: 'Bearer abcdefghijklmnop',
      profile: {
        refresh_token: 'refresh123456789',
        CreditCard: '4111111111111111',
        CVV: '123',
        email: 'john.doe@gmail.com',
        phone: '0901234567',
      },
      users: [
        {
          jwt: 'jwt123456789',
        },
      ],
    };

    const result = safeLog(payload);
    expect(result.password).toBe('********');
    expect(result.profile.CVV).toBe('***');
    expect(result.profile.email).toBe('j******e@gmail.com');
  });

  it('should handle edge cases and non-string types', () => {
    const payload = {
      name: 'John',
      age: 30,
      isActive: true,
      data: null,
      meta: undefined,
      emptyObj: {},
      emptyArr: [],
    };

    const result = safeLog(payload);
    expect(result).toEqual(payload);
  });

  it('should handle deep nesting', () => {
    const payload = {
      level1: {
        password: '123',
        level2: {
          token: 'abc',
        },
      },
    };

    const result = safeLog(payload);
    expect(result.level1.password).toBe('********');
    expect(result.level1.level2.token).toBe('abc'); // Too short to mask
  });

  it('should mask AWS and SMTP fields with different casing', () => {
    const payload = {
      awsAccessKeyId: 'AKIA1234567890',
      AWS_ACCESS_KEY_ID: 'AKIA1234567890',
      awsSecretAccessKey: 'superSecretKey123',
      AWS_SECRET_ACCESS_KEY: 'superSecretKey123',
      smtpUsername: 'user@example.com',
      SMTP_USERNAME: 'user@example.com',
      smtpPassword: 'smtpPassword123',
      SMTP_PASSWORD: 'smtpPassword123',
      SES_SMTP_USERNAME: 'sesUser@example.com',
      SES_SMTP_PASSWORD: 'sesPassword123',
    };

    const result = safeLog(payload);
    
    expect(result.awsAccessKeyId).not.toBe('AKIA1234567890');
    expect(result.AWS_ACCESS_KEY_ID).not.toBe('AKIA1234567890');
    
    expect(result.awsSecretAccessKey).not.toBe('superSecretKey123');
    expect(result.AWS_SECRET_ACCESS_KEY).not.toBe('superSecretKey123');
    
    expect(result.smtpUsername).not.toBe('user@example.com');
    expect(result.SMTP_USERNAME).not.toBe('user@example.com');
    
    expect(result.smtpPassword).not.toBe('smtpPassword123');
    expect(result.SMTP_PASSWORD).not.toBe('smtpPassword123');
    
    expect(result.SES_SMTP_USERNAME).not.toBe('sesUser@example.com');
    // Check if it was actually masked by token masker (minVisible: 4)
    // "sesUser@example.com" (length 19) -> 19 - 4 = 15 masked
    expect(result.SES_SMTP_USERNAME.length).toBe(19);
    expect(result.SES_SMTP_USERNAME.endsWith('.com')).toBe(true);
    
    expect(result.SES_SMTP_PASSWORD).not.toBe('sesPassword123');
  });

  it('should mask all new sensitive fields', () => {
    const payload = {
      secret_key: 'superSecret',
      api_secret: 'apiSecretValue',
      client_id: 'clientIdValue',
      jwt_secret: 'jwtSecretValue',
      encryption_key: 'encryptionKeyValue',
      ssh_key: 'sshKeyValue',
      rsa_key: 'rsaKeyValue',
      master_key: 'masterKeyValue',
      salt: 'saltValue',
      encryption_password: 'encPassword',
      db_password: 'dbPassword',
      connection_string: 'dbConnectionString',
      ldap_bind_password: 'ldapPassword',
      stripe_key: 'stripeKeyValue',
      sendgrid_api_key: 'sendgridKeyValue',
      slack_webhook_url: 'slackUrlValue',
      ssn: '123-456-7890',
      passport_number: 'passport123',
      drivers_license: 'DL12345',
      dob: '1990-01-01',
      card_number: '1234123412341234',
      cvc: '123',
      account_number: '1234567890',
      routing_number: '0987654321',
    };

    const result = safeLog(payload);

    // Simple check: make sure none are the original value
    Object.keys(payload).forEach(key => {
      expect(result[key as keyof typeof payload]).not.toBe(payload[key as keyof typeof payload]);
    });

    // Check specific maskers
    expect(result.encryption_password).toBe('********');
    expect(result.db_password).toBe('********');
    expect(result.ldap_bind_password).toBe('********');
    expect(result.cvc).toBe('***');
  });

  it('should allow registering a custom field masker', () => {
    const payload = {
      mySecretField: 'secretValue',
    };
    
    // Register custom masker
    registerFieldMasker('mySecretField', (value) => 'customMasked');
    
    const result = safeLog(payload);
    expect(result.mySecretField).toBe('customMasked');
  });

  it('should use maskToken as default when registering a field masker without a masker function', () => {
    const payload = {
      defaultSecretField: 'secretValue1234',
    };
    
    // Register with default masker
    registerFieldMasker('defaultSecretField');
    
    const result = safeLog(payload);
    // maskToken uses minVisible: 4, visiblePercent: 0.1
    // "secretValue1234" (length 15) -> 15 * 0.1 = 1.5 -> minVisible 4 visible
    // expected: ***********1234
    expect(result.defaultSecretField).toBe('***********1234');
  });
});
