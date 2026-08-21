import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react()],
  test: {
    // Node by default; DOM tests opt in with a `@vitest-environment jsdom`
    // docblock, so the fast codec tests never pay for a jsdom bootstrap.
    include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'],
    environment: 'node',
    globals: true,
  },
})
