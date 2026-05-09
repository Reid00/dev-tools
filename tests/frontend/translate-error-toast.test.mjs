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

function loadTranslationGlobals({ fetchImpl, input = 'hello', from = 'auto', to = 'zh' } = {}) {
  const html = readHtml();
  const script = ['apiCall', 'formatTranslateErrorMessage', 'doTranslate']
    .map((name) => extractNamedFunctionSource(html, name))
    .join('\n\n');

  const toasts = [];
  const elements = {
    'translate-input': { value: input },
    'translate-from': { value: from },
    'translate-to': { value: to },
    'translate-output': { value: '' },
  };

  const context = {
    globalThis: {},
    window: {},
    document: {
      getElementById(id) {
        return elements[id] ?? null;
      },
      addEventListener() {},
      querySelector() {
        return null;
      },
      querySelectorAll() {
        return [];
      },
      createElement() {
        return {
          className: '',
          textContent: '',
          style: {},
          appendChild() {},
          remove() {},
          classList: {
            add() {},
            remove() {},
            toggle() {},
          },
        };
      },
      body: {
        appendChild() {},
        removeChild() {},
        style: {},
      },
    },
    fetch: fetchImpl,
    navigator: {},
    JSON,
    Error,
    console,
    setTimeout() {},
    clearTimeout() {},
  };

  vm.createContext(context);
  vm.runInContext(
    `${script}; globalThis.__loaded = { apiCall, formatTranslateErrorMessage, doTranslate };`,
    context
  );

  const showToast = (message, type = 'error') => {
    toasts.push({ message, type });
  };

  context.showToast = showToast;
  context.globalThis.showToast = showToast;

  return {
    ...context.globalThis.__loaded,
    toasts,
    elements,
  };
}

test('maps local network error category to a friendly network toast', () => {
  const { formatTranslateErrorMessage } = loadTranslationGlobals();
  const error = new Error('connection refused');
  error.translateErrorType = 'network';

  assert.equal(
    formatTranslateErrorMessage(error),
    '翻译服务暂时不可用（网络请求失败）'
  );
});

test('maps local parse error category to a friendly parse toast', () => {
  const { formatTranslateErrorMessage } = loadTranslationGlobals();
  const error = new Error('unexpected eof');
  error.translateErrorType = 'parse';

  assert.equal(
    formatTranslateErrorMessage(error),
    '翻译服务返回异常（响应解析失败）'
  );
});

test('maps local upstream error category to a friendly upstream toast', () => {
  const { formatTranslateErrorMessage } = loadTranslationGlobals();
  const error = new Error('raw upstream backend wording');
  error.translateErrorType = 'upstream';

  assert.equal(
    formatTranslateErrorMessage(error),
    '翻译服务暂时不可用（上游服务返回错误）'
  );
});

test('falls back to the original reason for unknown translation errors', () => {
  const { formatTranslateErrorMessage } = loadTranslationGlobals();

  assert.equal(
    formatTranslateErrorMessage(new Error('服务端返回了未知格式')),
    '翻译失败（服务端返回了未知格式）'
  );
});

test('falls back to a generic retry message when reason is empty', () => {
  const { formatTranslateErrorMessage } = loadTranslationGlobals();

  assert.equal(
    formatTranslateErrorMessage({}),
    '翻译失败，请稍后重试'
  );
});

test('translation upstream failure shows exactly one friendly toast', async () => {
  const { doTranslate, toasts } = loadTranslationGlobals({
    fetchImpl: async () => ({
      ok: false,
      async json() {
        return { error: 'raw upstream backend wording' };
      },
    }),
  });

  await doTranslate();

  assert.deepEqual(toasts, [
    { message: '翻译服务暂时不可用（上游服务返回错误）', type: 'error' },
  ]);
});

test('translation native request failure maps to one friendly network toast', async () => {
  const { doTranslate, toasts } = loadTranslationGlobals({
    fetchImpl: async () => {
      throw new Error('connection refused');
    },
  });

  await doTranslate();

  assert.deepEqual(toasts, [
    { message: '翻译服务暂时不可用（网络请求失败）', type: 'error' },
  ]);
});

test('translation native parse failure maps to one friendly parse toast', async () => {
  const { doTranslate, toasts } = loadTranslationGlobals({
    fetchImpl: async () => ({
      ok: true,
      async json() {
        throw new Error('unexpected eof');
      },
    }),
  });

  await doTranslate();

  assert.deepEqual(toasts, [
    { message: '翻译服务返回异常（响应解析失败）', type: 'error' },
  ]);
});

test('apiCall still shows raw backend errors for non-translation callers', async () => {
  const { apiCall, toasts } = loadTranslationGlobals({
    fetchImpl: async () => ({
      ok: false,
      async json() {
        return { error: '请求失败: bad gateway' };
      },
    }),
  });

  await assert.rejects(apiCall('/api/time/now', {}), /请求失败: bad gateway/);

  assert.deepEqual(toasts, [
    { message: '请求失败: bad gateway', type: 'error' },
  ]);
});
