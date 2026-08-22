/**
 * Phase 3.5's promise, in a real browser: one byte typed into layer 4 rebuilds
 * every other layer, because no layer holds a copy of anything.
 *
 * This is the demonstration an interviewer can falsify in five seconds, so it is
 * worth having a test that would notice if it stopped being true.
 */

import { expect, test } from '@playwright/test'

/** The ARP opcode's low byte: 14 bytes of Ethernet, six of ARP, then one. */
const OPCODE_LOW = 21

test('typing over the ARP opcode turns a request into a reply everywhere', async ({ page }) => {
  await page.goto('#/lesson/arp')

  await expect(page.locator('.packet-tab-summary').first()).toHaveText('Who has 10.0.0.2? Tell 10.0.0.1')
  await expect(page.locator('.flow-label').first()).toHaveText('Who has 10.0.0.2? Tell 10.0.0.1')

  await page.getByLabel(`Byte ${OPCODE_LOW}, value 0x01`).click()
  await page.keyboard.press('0')
  // One nibble is not a byte: the cell shows the half-typed value and nothing
  // downstream has moved yet.
  await expect(page.locator('.hex-cell.is-typing')).toHaveText('0_')
  await expect(page.locator('.packet-tab-summary').first()).toHaveText('Who has 10.0.0.2? Tell 10.0.0.1')

  await page.keyboard.press('2')

  // Layer 3, layer 2 and the tab all re-read the same new buffer.
  await expect(page.locator('[data-field-id="arp.opcode"]')).toContainText('2 (Reply)')
  await expect(page.locator('.packet-tab-summary').first()).toHaveText('10.0.0.1 is at aa:bb:cc:00:00:01')
  await expect(page.locator('.flow-label').first()).toHaveText('10.0.0.1 is at aa:bb:cc:00:00:01')

  // Layer 4 marks the byte, and the packet is flagged as no longer the lesson's.
  await expect(page.getByLabel(`Byte ${OPCODE_LOW}, value 0x02`)).toHaveClass(/is-edited/)
  await expect(page.locator('.edited-badge')).toBeVisible()

  // Reset restores the scenario's bytes — proof the edit never touched them.
  await page.getByRole('button', { name: /Reset to the scenario/ }).click()
  await expect(page.locator('.packet-tab-summary').first()).toHaveText('Who has 10.0.0.2? Tell 10.0.0.1')
  await expect(page.locator('.edited-badge')).toHaveCount(0)
})

test('a hand-edited length byte surfaces the decoder problem it causes', async ({ page }) => {
  await page.goto('#/lesson/arp')

  // The ARP hardware-address length. tshark calls the same edit a malformed
  // packet; see the hand-edited-frame case in tests/tshark-diff.test.ts.
  await page.getByLabel('Byte 18, value 0x06').click()
  await page.keyboard.press('f')
  await page.keyboard.press('f')

  const problems = page.getByRole('list', { name: 'Decoder problems' })
  await expect(problems).toContainText('6-byte hardware addresses')
  await expect(page.locator('.hex-cell.is-error')).toHaveCount(1)
})
