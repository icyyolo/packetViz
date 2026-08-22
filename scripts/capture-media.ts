/**
 * Regenerates `docs/media` by driving the built site in a real browser.
 *
 * Determinism is the point: the timeline is seeked to a fixed `t` rather than
 * played, animations and transitions are disabled, the viewport and device scale
 * are pinned, and no screenshot waits on a clock. Running this twice produces
 * identical PNGs, so a regenerated README is a diff of what changed on screen
 * and not a diff of when the shot was taken.
 *
 * Run with `npm run media` (Node's own TypeScript stripping — no build step).
 */

import { spawn } from 'node:child_process'
import { execFileSync } from 'node:child_process'
import { mkdirSync, rmSync, readdirSync, renameSync } from 'node:fs'
import { join } from 'node:path'
import { chromium, type Page } from '@playwright/test'

const PORT = 4180
const BASE = `http://127.0.0.1:${PORT}/packetViz/`
const OUT = 'docs/media'
const VIEWPORT = { width: 1360, height: 900 }

/** Kills every animation, so a screenshot is a function of the DOM alone. */
const STILL = `
  *, *::before, *::after {
    animation: none !important;
    transition: none !important;
    caret-color: transparent !important;
  }
`

async function main(): Promise<void> {
  mkdirSync(OUT, { recursive: true })
  const server = await startPreview()

  const browser = await chromium.launch()
  try {
    await captureStills(browser)
    await captureHexEditGif(browser)
  } finally {
    await browser.close()
    server.kill('SIGTERM')
  }
  process.stdout.write(`\nmedia written to ${OUT}/\n`)
}

async function captureStills(browser: Awaited<ReturnType<typeof chromium.launch>>): Promise<void> {
  const context = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: 2 })
  const page = await context.newPage()

  await open(page, '#/')
  await shoot(page, 'home.png')

  // The four layers of the ARP lesson, at a fixed point on the timeline.
  await open(page, '#/lesson/arp')
  await seek(page, 620)
  await shoot(page, 'four-layers.png')

  // The signature feature: a field selected, its bytes lit up.
  await page.locator('[data-field-id="arp.src.proto_ipv4"]').first().click()
  await shoot(page, 'field-byte-link.png', '.panes')

  // The whole Phase 4 stack in one packet.
  await open(page, '#/lesson/dhcp')
  await page.locator('.packet-tab').nth(3).click()
  await shoot(page, 'dhcp-stack.png', '.panes')

  // A poisoned neighbour cache, which is the spoofing lesson's whole point.
  await open(page, '#/lesson/arp-spoofing')
  await seek(page, 1600)
  await shoot(page, 'arp-cache.png', '.cache-section')

  await context.close()
}

/** The demo: one byte typed into layer 4, and every layer following it. */
async function captureHexEditGif(
  browser: Awaited<ReturnType<typeof chromium.launch>>,
): Promise<void> {
  const videoDir = join(OUT, '.video')
  rmSync(videoDir, { recursive: true, force: true })

  const context = await browser.newContext({
    viewport: { width: 1100, height: 720 },
    recordVideo: { dir: videoDir, size: { width: 1100, height: 720 } },
  })
  const page = await context.newPage()
  await open(page, '#/lesson/arp')
  await page.locator('.pane-hex').scrollIntoViewIfNeeded()

  await page.waitForTimeout(700)
  await page.getByLabel('Byte 21, value 0x01').click()
  await page.waitForTimeout(700)
  await page.keyboard.press('0')
  await page.waitForTimeout(500)
  await page.keyboard.press('2')
  await page.waitForTimeout(1500)
  await page.getByRole('button', { name: /Reset to the scenario/ }).click()
  await page.waitForTimeout(900)

  await context.close() // flushes the video file

  const recorded = readdirSync(videoDir).find((name) => name.endsWith('.webm'))
  if (recorded === undefined) throw new Error('playwright wrote no video')
  const webm = join(videoDir, recorded)

  // 10 fps at 760px with a Bayer dither: a README GIF that stays under a
  // megabyte and still shows every layer moving on the same keystroke.
  execFileSync('ffmpeg', [
    '-y', '-loglevel', 'error', '-i', webm,
    '-vf',
    'fps=10,scale=760:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=64[p];' +
      '[b][p]paletteuse=dither=bayer:bayer_scale=3',
    join(OUT, 'demo.gif'),
  ])
  renameSync(webm, join(OUT, 'demo.webm'))
  rmSync(videoDir, { recursive: true, force: true })
  process.stdout.write('  demo.gif\n')
}

async function open(page: Page, hash: string): Promise<void> {
  await page.goto(`${BASE}${hash}`)
  await page.addStyleTag({ content: STILL })
  await page.locator('main, .lesson, .home').first().waitFor()
}

/** Sets the virtual clock, which every view is a pure function of. */
async function seek(page: Page, tMs: number): Promise<void> {
  await page.getByLabel('Timeline position in milliseconds').fill(String(tMs))
}

async function shoot(page: Page, name: string, selector?: string): Promise<void> {
  const target = selector === undefined ? page : page.locator(selector)
  await target.screenshot({ path: join(OUT, name), ...(selector === undefined ? { fullPage: false } : {}) })
  process.stdout.write(`  ${name}\n`)
}

function startPreview(): Promise<ReturnType<typeof spawn>> {
  execFileSync('npm', ['run', 'build'], { stdio: 'inherit' })
  const server = spawn('npm', ['run', 'preview', '--', '--port', String(PORT), '--strictPort'], {
    stdio: 'ignore',
  })

  return new Promise((resolve, reject) => {
    const started = Date.now()
    const poll = (): void => {
      fetch(BASE)
        .then(() => resolve(server))
        .catch(() => {
          if (Date.now() - started > 60_000) reject(new Error('preview server did not start'))
          else setTimeout(poll, 250)
        })
    }
    poll()
  })
}

await main()
