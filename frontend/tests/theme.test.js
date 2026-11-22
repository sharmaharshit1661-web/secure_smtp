import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { THEME_KEY, resolveTheme, readThemePreference, saveThemePreference, applyTheme } from '../src/utils/theme.js';

test('explicit choice wins over system preference, invalid or missing choices follow the system', () => {
  for (const systemDark of [true, false]) {
    assert.equal(resolveTheme('dark', systemDark), 'dark');
    assert.equal(resolveTheme('light', systemDark), 'light');
    for (const preference of [null, undefined, 'invalid']) {
      assert.equal(resolveTheme(preference, systemDark), systemDark ? 'dark' : 'light');
    }
  }
});

test('a selected theme survives reload and storage failures remain recoverable', () => {
  const data = new Map();
  const storage = { getItem: key => data.get(key), setItem: (key, value) => data.set(key, value) };
  saveThemePreference(storage, 'dark');
  assert.equal(readThemePreference(storage), 'dark');
  saveThemePreference(storage, 'light');
  assert.equal(readThemePreference(storage), 'light');
  data.set(THEME_KEY, 'invalid');
  assert.equal(readThemePreference(storage), null);
  const blocked = { getItem() { throw Error('blocked'); }, setItem() { throw Error('blocked'); } };
  assert.equal(readThemePreference(blocked), null);
  assert.doesNotThrow(() => saveThemePreference(blocked, 'dark'));
  assert.doesNotThrow(() => saveThemePreference(null, 'dark'));
});

function documentStub() {
  const meta = { content: '', setAttribute(key, value) { this[key] = value; } };
  return { documentElement: { dataset: {}, style: {} }, querySelector: () => meta, meta };
}

test('pre-paint initialization and runtime switching agree, even when storage access throws', () => {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  const bootstrap = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  for (const preference of ['light', 'dark', null, 'invalid', 'blocked']) {
    for (const systemDark of [false, true]) {
      const document = documentStub();
      const context = {
        document, matchMedia: () => ({ matches: systemDark }),
        get localStorage() {
          if (preference === 'blocked') throw Error('blocked');
          return { getItem: () => preference };
        },
      };
      vm.runInNewContext(bootstrap, context);
      const expected = resolveTheme(preference, systemDark);
      assert.equal(document.documentElement.dataset.theme, expected);
      const initial = document.meta.content;
      applyTheme(expected, document);
      assert.equal(document.meta.content, initial);
      assert.equal(document.documentElement.style.colorScheme, expected);
      applyTheme(expected === 'light' ? 'dark' : 'light', document);
      assert.notEqual(document.meta.content, initial);
    }
  }
});

const css = ['index.css', 'reference-theme.css', 'theme.css'].map(file =>
  readFileSync(new URL(`../src/${file}`, import.meta.url), 'utf8')).join('\n');
function tokensFor(theme) {
  const tokens = {};
  for (const block of css.matchAll(/:root(?:\[data-theme="(dark)"\])?\s*\{([^}]+)\}/g)) {
    if (block[1] && theme !== 'dark') continue;
    for (const [, key, value] of block[2].matchAll(/(--[\w-]+):\s*([^;]+);/g)) tokens[key] = value.trim();
  }
  function resolve(key) {
    const value = tokens[key];
    assert.ok(value, `Missing theme token ${key}`);
    return value.startsWith('var(') ? resolve(value.slice(4, -1)) : value;
  }
  return resolve;
}
function luminance(hex) {
  const rgb = hex.match(/^#([\da-f]{2})([\da-f]{2})([\da-f]{2})$/i);
  assert.ok(rgb, `Expected opaque color: ${hex}`);
  const [r, g, b] = rgb.slice(1).map(v => parseInt(v, 16) / 255).map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4);
  return .2126 * r + .7152 * g + .0722 * b;
}
function contrast(a, b) {
  const values = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (values[0] + .05) / (values[1] + .05);
}

for (const theme of ['light', 'dark']) {
  test(`${theme} text, status labels and primary actions meet AA contrast`, () => {
    const color = tokensFor(theme);
    const check = (fg, bg, minimum = 4.5) => {
      const ratio = contrast(color(fg), color(bg));
      assert.ok(ratio >= minimum, `${fg} on ${bg}: ${ratio.toFixed(2)} < ${minimum}`);
    };
    for (const surface of ['--bg-canvas', '--bg-surface', '--bg-elevated', '--bg-inset', '--bg-input']) {
      for (const text of ['--text-primary', '--text-secondary', '--text-muted']) check(text, surface);
      check('--interactive-focus', surface, 3);
      for (const tier of ['critical', 'high', 'medium', 'low', 'clean', 'info']) check(`--sev-${tier}`, surface, 3);
    }
    check('--action-text', '--action-bg');
    check('--action-text', '--action-hover');
    check('--notice-error-text', '--notice-error-bg');
    for (const tier of ['critical', 'high', 'medium', 'low', 'clean', 'info']) check(`--sev-${tier}`, `--sev-${tier}-soft`);
  });
}
