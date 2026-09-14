const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Requires a running test backend with at least one saved scan, and Playwright.
// node tests/mobile-layout.cjs TOKEN_FILE [PLAYWRIGHT_MODULE] [BASE_URL] [SCREENSHOT_DIR]
const [tokenFile, playwrightModule = 'playwright', base = 'http://127.0.0.1:8768', shots] =
  process.argv.slice(2);
if (!tokenFile) throw new Error('Provide the path to the test backend token file.');
const { chromium } = require(playwrightModule);

(async () => {
  const token = fs.readFileSync(tokenFile, 'utf8').trim();
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    await page.goto(`${base}/#token=${encodeURIComponent(token)}`);
    await page.getByRole('heading', { name: 'Il tuo perimetro MCP.' }).waitFor();
    assert.equal(new URL(page.url()).hash, '', 'Token fragment should be consumed');
    await page.getByRole('button', { name: 'File Scanner', exact: true }).click();
    await page.locator('.processed-table tbody tr').first().waitFor();
    for (const width of [1440, 1024, 768, 390, 360]) {
      await page.setViewportSize({ width, height: 844 });
      await page.waitForTimeout(350);
      const dimensions = await page.evaluate(() => {
        const table = document.querySelector('.processed-registry .table-scroll');
        return {
          viewport: window.innerWidth,
          document: document.documentElement.scrollWidth,
          tableScroll: table.scrollWidth,
          tableWidth: table.clientWidth,
        };
      });
      assert.ok(
        dimensions.document <= dimensions.viewport,
        `Page overflow at ${width}: ${JSON.stringify(dimensions)}`,
      );
      if (width <= 390)
        assert.ok(
          dimensions.tableScroll > dimensions.tableWidth,
          'The registry should scroll inside its container',
        );
      console.log(JSON.stringify({ width, ...dimensions }));
      if (shots && width === 390) {
        fs.mkdirSync(shots, { recursive: true });
        await page.screenshot({
          path: path.join(shots, 'scanner-mobile-fixed.png'),
          fullPage: true,
        });
      }
    }
    for (const name of ['Componenti MCP', 'Registro audit', 'Policy e controlli']) {
      await page.getByRole('button', { name: 'Apri navigazione', exact: true }).click();
      await page.getByRole('button', { name, exact: true }).click();
      await page.waitForTimeout(400);
      assert.equal(
        await page.evaluate(() => document.documentElement.scrollWidth > innerWidth),
        false,
        `${name} overflows on mobile`,
      );
    }
    assert.deepEqual(pageErrors, [], 'No uncaught browser exceptions');
    console.log('Mobile layout checks passed.');
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
