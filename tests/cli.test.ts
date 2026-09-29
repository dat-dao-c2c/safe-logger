import { describe, it, expect } from 'vitest';
import { runCli, type CliIo } from '../src/cli-core.js';

function io(overrides: Partial<CliIo> = {}): CliIo {
  return {
    env: {},
    readStdin: async () => undefined,
    ...overrides,
  };
}

describe('safe-log CLI', () => {
  it('masks an environment variable by name without printing it raw', async () => {
    const result = await runCli(['API_KEY'], io({ env: { API_KEY: 'sk_live_abcdefghijkl' } }));

    expect(result.code).toBe(0);
    expect(result.stdout).toBe('API_KEY=****************ijkl\n');
  });

  it('fails when the environment variable is not set', async () => {
    const result = await runCli(['API_KEY'], io());

    expect(result.code).toBe(1);
    expect(result.stderr).toContain('API_KEY is not set');
  });

  it('masks NAME=VALUE arguments', async () => {
    const result = await runCli(['DB_PASSWORD=hunter2hunter2'], io());

    expect(result.stdout).toBe('DB_PASSWORD=********\n');
  });

  it('masks a JSON argument', async () => {
    const result = await runCli(['{"API_KEY":"123456","name":"svc"}'], io());

    expect(result.code).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({ API_KEY: '******', name: 'svc' });
  });

  it('pretty-prints JSON with --pretty', async () => {
    const result = await runCli(['-p', '{"token":"abcdefghijkl"}'], io());

    expect(result.stdout).toBe('{\n  "token": "********ijkl"\n}\n');
  });

  it('handles multiple arguments', async () => {
    const result = await runCli(
      ['API_KEY', 'LOG_LEVEL=debug'],
      io({ env: { API_KEY: 'abcdefghijkl' } }),
    );

    expect(result.stdout).toBe('API_KEY=********ijkl\nLOG_LEVEL=debug\n');
  });

  it('masks JSON from stdin', async () => {
    const result = await runCli(
      [],
      io({ readStdin: async () => '{"password":"x","items":[{"apiKey":"abcdefghijkl"}]}\n' }),
    );

    expect(JSON.parse(result.stdout)).toEqual({
      password: '********',
      items: [{ apiKey: '********ijkl' }],
    });
  });

  it('masks env / .env style lines from stdin and keeps other lines', async () => {
    const input = [
      '# comment',
      'export AWS_SECRET_ACCESS_KEY="abcdefghijklmnop"',
      'CONNECTION_STRING=postgres://u:p@host:5432/db?a=b',
      'HOME=/home/user',
      '',
    ].join('\n');

    const result = await runCli([], io({ readStdin: async () => input }));

    expect(result.stdout).toBe(
      [
        '# comment',
        'export AWS_SECRET_ACCESS_KEY=************mnop',
        `CONNECTION_STRING=${'*'.repeat(27)}?a=b`,
        'HOME=/home/user',
        '',
      ].join('\n'),
    );
  });

  it('does not echo input in invalid JSON errors', async () => {
    const result = await runCli(['{"API_KEY": "sk_live_secret'], io());

    expect(result.code).toBe(1);
    expect(result.stderr).toBe('safe-log: invalid JSON input\n');
    expect(result.stderr).not.toContain('sk_live');
  });

  it('reports stdin read errors (e.g. size limit)', async () => {
    const result = await runCli(
      [],
      io({ readStdin: async () => { throw new Error('input exceeds 10485760 bytes'); } }),
    );

    expect(result.code).toBe(1);
    expect(result.stderr).toContain('input exceeds');
  });

  it('rejects unknown options and invalid arguments', async () => {
    expect((await runCli(['--nope'], io())).code).toBe(2);
    expect((await runCli(['not valid!'], io())).code).toBe(2);
  });

  it('errors with usage when there is no input', async () => {
    const result = await runCli([], io());

    expect(result.code).toBe(2);
    expect(result.stderr).toContain('Usage:');
  });

  it('prints help', async () => {
    const result = await runCli(['--help'], io());

    expect(result.code).toBe(0);
    expect(result.stdout).toContain('Usage:');
    expect(result.stdout).toContain('safe-log NAME');
  });

  it.each(['safe-logger', 'sanity-logger', 'my-logger', 'sanityLogger', 'safeLogger', 'myLogger'])(
    'uses the invoked alias %s in help and errors',
    async (commandName) => {
      const help = await runCli(['--help'], io({ commandName }));
      const error = await runCli(['MISSING'], io({ commandName }));

      expect(help.stdout).toContain(`  ${commandName} NAME`);
      expect(help.stdout).toContain(`<cmd> | ${commandName}`);
      expect(error.stderr).toBe(`${commandName}: environment variable MISSING is not set\n`);
    },
  );
});
