/**
 * The pages exist, are reachable, and render what the registry says they hold.
 *
 * Deliberately shallow: this is the test that fails when a route breaks or a
 * build stops shipping something. The depth lives in `field-byte-link.spec.ts`.
 */

import { expect, test } from '@playwright/test'
import { LESSONS } from '../src/lessons/index.ts'
import { compileScenario } from '../src/scenario/compile.ts'

test('the home page lists every lesson, plus the import and reference cards', async ({ page }) => {
  await page.goto('#/')

  for (const lesson of LESSONS) {
    await expect(page.getByRole('link', { name: lesson.title })).toBeVisible()
  }
  await expect(page.getByRole('link', { name: /Open your own/i })).toBeVisible()
})

for (const lesson of LESSONS) {
  test(`the ${lesson.slug} lesson loads from its own URL`, async ({ page }) => {
    const timeline = compileScenario(lesson.scenario)
    await page.goto(`#/lesson/${lesson.slug}`)

    await expect(page.getByRole('heading', { level: 1 })).toHaveText(lesson.title)
    await expect(page.locator('.packet-tab')).toHaveCount(timeline.packets.length)

    // Every summary on a tab came out of the decode, so this also checks that
    // the build shipped a working codec rather than a working page.
    await expect(page.locator('.packet-tab-summary')).toHaveText(
      timeline.packets.map((packet) => packet.summary),
    )

    // All four layers are present.
    await expect(page.locator('.topology')).toBeVisible()
    await expect(page.locator('.flow')).toBeVisible()
    await expect(page.locator('[role="tree"]')).toBeVisible()
    await expect(page.locator('.hex-grid')).toBeVisible()

    // And nothing the decoder produced is an error the lesson ships with.
    await expect(page.locator('.problem.is-error')).toHaveCount(0)
  })
}

test('the import page renders its dropzone', async ({ page }) => {
  await page.goto('#/import')
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
})

test('an unknown lesson slug explains itself instead of going blank', async ({ page }) => {
  await page.goto('#/lesson/not-a-lesson')
  await expect(page.getByText(/may not be built yet/i)).toBeVisible()
})

/**
 * The hex column is sized by its content, so a long field name can widen it
 * until the field tree beside it is squeezed to nothing — which is exactly what
 * the DHCP lesson did the first time this suite ran. Both widths are checked on
 * the widest lesson.
 */
for (const width of [1280, 390]) {
  test(`the DHCP lesson lays out with no horizontal scroll at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    await page.goto('#/lesson/dhcp')
    await expect(page.locator('.hex-grid')).toBeVisible()

    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    )
    expect(overflow).toBeLessThanOrEqual(0)

    // Every pane has real width: no column collapsed to zero.
    for (const pane of ['.pane-tree', '.pane-hex', '.pane-detail']) {
      const box = await page.locator(pane).boundingBox()
      expect(box?.width ?? 0, pane).toBeGreaterThan(100)
    }
  })
}
