import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.join(__dirname, '..', '..', 'static', 'index.html');

function readHtml() {
  return fs.readFileSync(htmlPath, 'utf8');
}

function extractNamedFunctionSource(html, functionName) {
  const startToken = [`async function ${functionName}(`, `function ${functionName}(`]
    .map((token) => ({ token, index: html.indexOf(token) }))
    .find(({ index }) => index !== -1);

  assert.ok(startToken, `Expected function ${functionName} in static/index.html`);

  const start = startToken.index;
  let parenDepth = 0;
  let bodyStart = -1;
  for (let i = start; i < html.length; i++) {
    const char = html[i];
    if (char === '(') parenDepth += 1;
    if (char === ')') {
      parenDepth -= 1;
      continue;
    }
    if (char === '{' && parenDepth === 0) {
      bodyStart = i;
      break;
    }
  }

  assert.notEqual(bodyStart, -1, `Expected opening brace for ${functionName}`);

  let depth = 0;
  for (let i = bodyStart; i < html.length; i++) {
    const char = html[i];
    if (char === '{') depth += 1;
    if (char === '}') {
      depth -= 1;
      if (depth === 0) {
        return html.slice(start, i + 1);
      }
    }
  }

  assert.fail(`Could not extract ${functionName} from static/index.html`);
}

function loadTranslateHistoryGlobals({
  fetchImpl = async () => ({
    ok: true,
    async json() {
      return { result: '你好', from: 'en', to: 'zh' };
    },
  }),
  input = 'hello',
  from = 'auto',
  to = 'zh',
  initialStorage = {},
} = {}) {
  const html = readHtml();
  const script = [
    'updateCharCount',
    'formatTranslateErrorMessage',
    'getTranslateHistory',
    'renderTranslateHistory',
    'saveTranslateHistoryEntry',
    'restoreTranslateHistory',
    'clearTranslateHistory',
    'doTranslate',
  ]
    .map((name) => extractNamedFunctionSource(html, name))
    .join('\n\n');

  const storage = new Map(Object.entries(initialStorage));
  const toasts = [];
  const elements = {
    'translate-input': { value: input },
    'translate-from': { value: from },
    'translate-to': { value: to },
    'translate-output': { value: '' },
    'translate-char-count': { textContent: '0' },
    'translate-history-list': { innerHTML: '' },
    'translate-history-empty': {
      classList: {
        add() {},
        remove() {},
        toggle() {},
      },
    },
    'translate-history-panel': {
      classList: {
        add() {},
        remove() {},
        toggle() {},
      },
    },
    'translate-history-toggle-text': { textContent: '' },
  };

  const SafeStorage = {
    get(key) {
      return storage.has(key) ? storage.get(key) : null;
    },
    set(key, value) {
      storage.set(key, value);
      return true;
    },
    remove(key) {
      storage.delete(key);
      return true;
    },
    getJSON(key, defaultValue) {
      if (!storage.has(key)) return defaultValue;
      try {
        return JSON.parse(storage.get(key));
      } catch {
        return defaultValue;
      }
    },
    setJSON(key, value) {
      storage.set(key, JSON.stringify(value));
      return true;
    },
  };

  const context = {
    globalThis: {},
    window: {
      matchMedia() {
        return { matches: false };
      },
    },
    document: {
      getElementById(id) {
        return elements[id] ?? null;
      },
    },
    SafeStorage,
    fetch: fetchImpl,
    showToast(message, type = 'error') {
      toasts.push({ message, type });
    },
    escapeHtml(value) {
      return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    },
    JSON,
    Date,
    Error,
    console,
  };

  vm.createContext(context);
  vm.runInContext(
    `const TRANSLATE_HISTORY_KEY = 'translate_history';\nconst TRANSLATE_HISTORY_LIMIT = 7;\nlet translateHistoryCollapsed = false;\n${script}\nglobalThis.__loaded = { getTranslateHistory, renderTranslateHistory, saveTranslateHistoryEntry, restoreTranslateHistory, clearTranslateHistory, doTranslate };`,
    context
  );

  return {
    ...context.globalThis.__loaded,
    storage,
    elements,
    toasts,
  };
}

test('successful translation writes one normalized history entry', async () => {
  const { doTranslate, storage } = loadTranslateHistoryGlobals({
    fetchImpl: async () => ({
      ok: true,
      async json() {
        return { result: '你好，世界', from: 'en', to: 'zh' };
      },
    }),
    input: 'Hello world',
    from: 'auto',
    to: 'zh',
  });

  await doTranslate();

  const saved = JSON.parse(storage.get('translate_history'));
  assert.equal(saved.length, 1);
  assert.equal(saved[0].sourceText, 'Hello world');
  assert.equal(saved[0].translatedText, '你好，世界');
  assert.equal(saved[0].from, 'en');
  assert.equal(saved[0].to, 'zh');
});

test('saveTranslateHistoryEntry dedupes by source text and direction and keeps the newest copy', () => {
  const { saveTranslateHistoryEntry, getTranslateHistory } = loadTranslateHistoryGlobals();

  saveTranslateHistoryEntry({
    id: 1,
    timestamp: '2026-05-09T10:00:00.000Z',
    sourceText: 'hello',
    translatedText: '你好',
    from: 'en',
    to: 'zh',
  });

  saveTranslateHistoryEntry({
    id: 2,
    timestamp: '2026-05-09T11:00:00.000Z',
    sourceText: 'hello',
    translatedText: '您好',
    from: 'en',
    to: 'zh',
  });

  const history = getTranslateHistory();
  assert.equal(history.length, 1);
  assert.equal(history[0].id, 2);
  assert.equal(history[0].translatedText, '您好');
});

test('saveTranslateHistoryEntry keeps only the latest seven items', () => {
  const { saveTranslateHistoryEntry, getTranslateHistory } = loadTranslateHistoryGlobals();

  for (let i = 1; i <= 8; i += 1) {
    saveTranslateHistoryEntry({
      id: i,
      timestamp: `2026-05-09T10:00:0${i}.000Z`,
      sourceText: `source-${i}`,
      translatedText: `target-${i}`,
      from: 'en',
      to: 'zh',
    });
  }

  const history = getTranslateHistory();
  assert.equal(history.length, 7);
  assert.equal(history[0].sourceText, 'source-8');
  assert.equal(history[6].sourceText, 'source-2');
});

test('restoreTranslateHistory refills the translation form and updates the char count', () => {
  const { saveTranslateHistoryEntry, restoreTranslateHistory, elements } = loadTranslateHistoryGlobals({
    input: '',
    from: 'auto',
    to: 'auto',
  });

  saveTranslateHistoryEntry({
    id: 42,
    timestamp: '2026-05-09T12:00:00.000Z',
    sourceText: 'restore me',
    translatedText: '恢复我',
    from: 'en',
    to: 'zh',
  });

  restoreTranslateHistory(42);

  assert.equal(elements['translate-input'].value, 'restore me');
  assert.equal(elements['translate-output'].value, '恢复我');
  assert.equal(elements['translate-from'].value, 'en');
  assert.equal(elements['translate-to'].value, 'zh');
  assert.equal(elements['translate-char-count'].textContent, 10);
});

test('clearTranslateHistory removes persisted entries', () => {
  const { saveTranslateHistoryEntry, clearTranslateHistory, getTranslateHistory, storage } = loadTranslateHistoryGlobals();

  saveTranslateHistoryEntry({
    id: 99,
    timestamp: '2026-05-09T13:00:00.000Z',
    sourceText: 'clear me',
    translatedText: '清空我',
    from: 'en',
    to: 'zh',
  });

  clearTranslateHistory();

  assert.equal(getTranslateHistory().length, 0);
  assert.equal(storage.has('translate_history'), false);
});

test('failed translation does not write history', async () => {
  const { doTranslate, storage, toasts } = loadTranslateHistoryGlobals({
    fetchImpl: async () => ({
      ok: false,
      async json() {
        return { error: 'raw upstream backend wording' };
      },
    }),
  });

  await doTranslate();

  assert.equal(storage.has('translate_history'), false);
  assert.equal(toasts.length, 1);
});
