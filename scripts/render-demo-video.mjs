import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require("playwright"));
} catch {
  throw new Error("Playwright is required for video rendering. Run npm install, then npm run demo:video.");
}

const root = path.resolve(".");
const outputDir = path.resolve("demo/output");
const outputVideo = path.join(outputDir, "pickbits-dependency-audit-demo.webm");
const outputPoster = path.join(outputDir, "pickbits-dependency-audit-demo-poster.png");
const port = 8791;
fs.mkdirSync(outputDir, { recursive: true });
const browserCandidates = [
  process.env.PICKBITS_AUDIT_BROWSER,
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
].filter(Boolean);
const executablePath = browserCandidates.find((candidate) => fs.existsSync(candidate));

const server = http.createServer((request, response) => {
  const url = new URL(request.url, `http://127.0.0.1:${port}`);
  const requested = decodeURIComponent(url.pathname === "/" ? "/demo/index.html" : url.pathname);
  const filePath = path.resolve(root, `.${requested}`);
  if (filePath !== root && !filePath.startsWith(`${root}${path.sep}`)) return response.writeHead(403).end("Forbidden");
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) return response.writeHead(404).end("Not found");
  const type = path.extname(filePath) === ".html" ? "text/html; charset=utf-8" : "application/octet-stream";
  response.writeHead(200, { "content-type": type, "cache-control": "no-store" });
  fs.createReadStream(filePath).pipe(response);
});

await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
let browser;
try {
  browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) });
  const context = await browser.newContext({ viewport: { width: 1920, height: 1080 }, recordVideo: { dir: outputDir, size: { width: 1920, height: 1080 } } });
  const page = await context.newPage();
  await page.goto(`http://127.0.0.1:${port}/demo/index.html?autoplay=1&sceneMs=4200`, { waitUntil: "load" });
  await page.waitForTimeout(900);
  await page.screenshot({ path: outputPoster });
  await page.waitForFunction(() => window.demoComplete === true, null, { timeout: 40000 });
  await page.waitForTimeout(900);
  const video = page.video();
  await page.close();
  await context.close();
  const rawVideoPath = await video.path();
  await video.saveAs(outputVideo);
  if (path.resolve(rawVideoPath) !== path.resolve(outputVideo) && fs.existsSync(rawVideoPath)) fs.rmSync(rawVideoPath);
  console.log(JSON.stringify({ video: outputVideo, poster: outputPoster }, null, 2));
} finally {
  if (browser) await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
