import { defineConfig } from "vite";

export default defineConfig({
  clearScreen: false,
  // The dev server may also read the repository root, where CHANGELOG.md lives.
  server: { port: 1420, strictPort: true, host: "127.0.0.1", fs: { allow: ["../../"] } },
  build: { target: "es2022" },
});
