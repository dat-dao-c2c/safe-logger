import { defineConfig } from 'tsup';

export default defineConfig([
    {
        // Library
        entry: ['src/index.ts'],
        format: ['cjs', 'esm'],
        dts: true,
    },
    {
        // CLI: ESM only (top-level await). The hashbang makes the output executable.
        entry: ['src/cli.ts'],
        format: ['esm'],
        target: 'node18',
    },
]);
