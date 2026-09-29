import { safeLog } from './safe-log.js';

export const DEFAULT_COMMAND_NAME = 'safe-log';

export function usage(command: string = DEFAULT_COMMAND_NAME): string {
    const rows: Array<[string, string]> = [
        [`${command} NAME`, 'Mask the value of environment variable NAME'],
        [`${command} NAME=VALUE`, 'Mask VALUE using the rules for field NAME'],
        [`${command} '{"API_KEY":"..."}'`, 'Mask a JSON object/array'],
        [`<cmd> | ${command}`, 'Mask stdin (JSON, or KEY=VALUE lines such as env / .env)'],
    ];
    const width = Math.max(...rows.map(([syntax]) => syntax.length)) + 2;
    const lines = rows.map(([syntax, text]) => `  ${syntax.padEnd(width)}${text}`);

    return `Usage:
${lines.join('\n')}

Options:
  -p, --pretty   Pretty-print JSON output
  -h, --help     Show this help

Masking is key-based: values are masked according to their field name.
Prefer NAME or stdin over NAME=VALUE: command-line arguments are visible
in shell history and process listings (ps).`;
}

/** Maximum accepted stdin size. */
export const MAX_INPUT_BYTES = 10 * 1024 * 1024;

export interface CliIo {
    env: Record<string, string | undefined>;
    /** Returns stdin contents, or undefined when stdin is a TTY. */
    readStdin: () => Promise<string | undefined>;
    /** Name the command was invoked as, used in help and error messages. */
    commandName?: string;
}

export interface CliResult {
    code: number;
    stdout: string;
    stderr: string;
}

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const ASSIGNMENT = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)=(.*)$/s;

function maskField(key: string, value: string): string {
    return String(safeLog({ [key]: value })[key]);
}

function unquote(value: string): string {
    const first = value[0];

    if (
        value.length >= 2 &&
        (first === '"' || first === "'") &&
        value[value.length - 1] === first
    ) {
        return value.slice(1, -1);
    }

    return value;
}

function looksLikeJson(text: string): boolean {
    const trimmed = text.trimStart();
    return trimmed.startsWith('{') || trimmed.startsWith('[');
}

/**
 * JSON.parse error messages can echo part of the input, which may be a
 * secret. Callers only ever see a generic message.
 */
function maskJson(text: string, pretty: boolean): string | undefined {
    let parsed: unknown;

    try {
        parsed = JSON.parse(text);
    } catch {
        return undefined;
    }

    return JSON.stringify(safeLog(parsed), null, pretty ? 2 : undefined);
}

/**
 * Masks KEY=VALUE lines (env, .env, `export KEY=VALUE`).
 * Other lines (comments, blanks, free text) are passed through unchanged.
 */
function maskAssignments(text: string): string {
    return text
        .split('\n')
        .map(line => {
            const match = ASSIGNMENT.exec(line);

            if (!match) {
                return line;
            }

            const prefix = line.startsWith('export') ? 'export ' : '';
            const key = match[1]!;
            const value = unquote(match[2]!);

            return `${prefix}${key}=${maskField(key, value)}`;
        })
        .join('\n');
}

function ok(stdout: string): CliResult {
    return { code: 0, stdout: stdout.endsWith('\n') ? stdout : `${stdout}\n`, stderr: '' };
}

/** Error messages are prefixed with the command name by runCli. */
function fail(message: string, code = 1): CliResult {
    return { code, stdout: '', stderr: `${message}\n` };
}

function maskText(text: string, pretty: boolean): CliResult {
    if (looksLikeJson(text)) {
        const json = maskJson(text, pretty);
        return json === undefined ? fail('invalid JSON input') : ok(json);
    }

    return ok(maskAssignments(text));
}

function maskArgument(arg: string, env: CliIo['env'], pretty: boolean): CliResult {
    if (looksLikeJson(arg)) {
        return maskText(arg, pretty);
    }

    if (ENV_NAME.test(arg)) {
        const value = env[arg];

        if (value === undefined) {
            return fail(`environment variable ${arg} is not set`);
        }

        return ok(`${arg}=${maskField(arg, value)}`);
    }

    const match = ASSIGNMENT.exec(arg);

    if (match) {
        return ok(maskAssignments(arg));
    }

    return fail('argument must be NAME, NAME=VALUE or JSON (see --help)', 2);
}

export async function runCli(argv: string[], io: CliIo): Promise<CliResult> {
    const command = io.commandName ?? DEFAULT_COMMAND_NAME;
    const result = await execute(argv, io, command);

    return result.stderr
        ? { ...result, stderr: `${command}: ${result.stderr}` }
        : result;
}

async function execute(argv: string[], io: CliIo, command: string): Promise<CliResult> {
    let pretty = false;
    const inputs: string[] = [];

    for (const arg of argv) {
        if (arg === '-h' || arg === '--help') {
            return ok(usage(command));
        }

        if (arg === '-p' || arg === '--pretty') {
            pretty = true;
            continue;
        }

        if (arg === '--') {
            continue;
        }

        if (arg.startsWith('-') && arg.length > 1) {
            return fail(`unknown option ${arg}`, 2);
        }

        inputs.push(arg);
    }

    if (inputs.length === 0) {
        let stdin: string | undefined;

        try {
            stdin = await io.readStdin();
        } catch (error) {
            return fail(error instanceof Error ? error.message : 'failed to read stdin');
        }

        if (stdin === undefined) {
            return fail(`no input\n\n${usage(command)}`, 2);
        }

        return maskText(stdin, pretty);
    }

    const results = inputs.map(input => maskArgument(input, io.env, pretty));
    const failed = results.find(result => result.code !== 0);

    if (failed) {
        return failed;
    }

    return {
        code: 0,
        stdout: results.map(result => result.stdout).join(''),
        stderr: '',
    };
}
