import { defineConfig, devices } from "@playwright/test";

// The judge page (demo/judge/), served by src/judge-server.ts on a test port.
const PORT = 8097;
export default defineConfig({
  testDir: "test",
  testMatch: "*.spec.mjs",
  forbidOnly: Boolean(process.env.CI),
  reporter: "list",
  use: { baseURL: `http://127.0.0.1:${PORT}` },
  webServer: { command: "node src/judge-server.ts", env: { PORT: String(PORT), HOST: "127.0.0.1" }, url: `http://127.0.0.1:${PORT}/healthz`, reuseExistingServer: false },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "phone", use: { ...devices["Pixel 7"] } },
  ],
});
