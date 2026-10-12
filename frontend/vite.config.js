import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: "http://localhost:8099", changeOrigin: true },
      "/ws": { target: "ws://localhost:8099", ws: true },
    },
  },
});
