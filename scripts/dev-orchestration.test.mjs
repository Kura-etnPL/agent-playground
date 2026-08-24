import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const packageJson = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);

test("root dev script starts both application workspaces with concurrently", () => {
  const devScript = packageJson.scripts?.dev ?? "";

  assert.match(devScript, /^concurrently\b/);
  assert.match(devScript, /--kill-others\b/);
  assert.match(devScript, /npm run dev --workspace @taskflow\/api/);
  assert.match(devScript, /npm run dev --workspace @taskflow\/web/);
  assert.ok(packageJson.devDependencies?.concurrently);
});
