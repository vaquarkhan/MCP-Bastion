import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: "src/index.ts",
      name: "McpGuardCore",
      fileName: "index",
      formats: ["es"],
    },
    target: "es2022",
    sourcemap: true,
    minify: false,
  },
});
