import { expect, test } from '@playwright/test'
import { holderColumns } from '../src/lab'

// What each side knows: the columns follow the diagram's lanes, so Client stays left of Server whichever side's key event arrives first.
test('the columns follow the lesson lanes, whatever order the key events arrive in', () => {
  const lanes = ['client', 'server']
  expect(holderColumns(['client', 'server'], lanes)).toEqual(['client', 'server'])
  expect(holderColumns(['server', 'client'], lanes)).toEqual(['client', 'server'])
  expect(holderColumns(['server', 'client', 'server'], lanes)).toEqual(['client', 'server'])
})

test('a holder that is not a lane follows the lanes, in the order it first appears', () => {
  expect(holderColumns(['hsm', 'server', 'reader', 'client'], ['client', 'server'])).toEqual(['client', 'server', 'hsm', 'reader'])
  expect(holderColumns(['server'], ['client', 'server'])).toEqual(['server'])
  expect(holderColumns(['b', 'a'], [])).toEqual(['b', 'a'])
})
