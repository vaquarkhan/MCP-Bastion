import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: "src/index.ts",
      name: "McpGuardCore",
      fileName: "index",
      formats: ["es"],
    },
    target: "node18",
    sourcemap: true,
    minify: false,
    // Node built-ins stay external — core is a Node MCP middleware, not a browser bundle.
    rollupOptions: {
      external: [/^node:/, "crypto"],
    },
  },
});
