#!/usr/bin/env node
import { basename } from 'node:path';
import { MAX_INPUT_BYTES, runCli } from './cli-core.js';

async function readStdin(): Promise<string | undefined> {
    if (process.stdin.isTTY) {
        return undefined;
    }

    const chunks: Buffer[] = [];
    let size = 0;

    for await (const chunk of process.stdin) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += buffer.length;

        if (size > MAX_INPUT_BYTES) {
            throw new Error(`input exceeds ${MAX_INPUT_BYTES} bytes`);
        }

        chunks.push(buffer);
    }

    return Buffer.concat(chunks).toString('utf8');
}

/**
 * npm installs one symlink per `bin` alias (safe-log, safeLogger, ...);
 * argv[1] is the alias that was invoked. Running dist/cli.js directly
 * falls back to the default name.
 */
function commandName(): string | undefined {
    const name = process.argv[1] ? basename(process.argv[1]).replace(/\.(c|m)?js$/, '') : '';
    return name && name !== 'cli' ? name : undefined;
}

const name = commandName();

const result = await runCli(process.argv.slice(2), {
    env: process.env,
    readStdin,
    ...(name ? { commandName: name } : {}),
});

process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
process.exitCode = result.code;
