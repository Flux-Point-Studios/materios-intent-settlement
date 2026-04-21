import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json-summary'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.d.ts',
        'src/types.ts',
        'src/index.ts',
        // connectMaterios opens a live ws — out of scope for unit tests;
        // covered by scripts/full-demo.ts integration path.
      ],
      thresholds: {
        // Team D brief: "Coverage gate: ≥80% on the orchestration helpers."
        lines: 80,
        functions: 80,
        branches: 75,
        statements: 80,
      },
    },
    testTimeout: 30_000,
  },
});
