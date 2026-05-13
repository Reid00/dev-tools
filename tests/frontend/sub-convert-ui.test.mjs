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
  for (let i = start; i < html.length; i += 1) {
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
  for (let i = bodyStart; i < html.length; i += 1) {
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

function loadSubscriptionGlobals({ subscriptionUrl = 'https://example.com/sub', template = 'singbox' } = {}) {
  const html = readHtml();
  const script = ['getSubPayloadFromInputs', 'formatTemplateBadgeText']
    .map((name) => extractNamedFunctionSource(html, name))
    .join('\n\n');

  const elements = {
    'sub-url': { value: subscriptionUrl },
    'sub-template': { value: template },
  };

  const context = {
    globalThis: {},
    document: {
      getElementById(id) {
        return elements[id] ?? null;
      },
    },
    JSON,
    Error,
    console,
  };

  vm.createContext(context);
  vm.runInContext(
    `${script}; globalThis.__loaded = { getSubPayloadFromInputs, formatTemplateBadgeText };`,
    context
  );

  return {
    ...context.globalThis.__loaded,
    elements,
  };
}

test('getSubPayloadFromInputs only sends subscription url, template, and file', () => {
  const { getSubPayloadFromInputs } = loadSubscriptionGlobals({
    subscriptionUrl: ' https://example.com/subscription ',
    template: 'default',
  });

  assert.deepEqual(JSON.parse(JSON.stringify(getSubPayloadFromInputs())), {
    subscription_url: 'https://example.com/subscription',
    template: 'default',
    file: 'default',
  });
});

test('formatTemplateBadgeText labels builtin templates', () => {
  const { formatTemplateBadgeText } = loadSubscriptionGlobals();

  assert.equal(
    formatTemplateBadgeText({
      name: 'default',
      source: 'builtin',
      reference_value: 'builtin/default.json',
    }),
    'default · 内置模板 · file=builtin/default.json'
  );
});

test('formatTemplateBadgeText labels remote templates', () => {
  const { formatTemplateBadgeText } = loadSubscriptionGlobals();

  assert.equal(
    formatTemplateBadgeText({
      name: 'custom',
      source: 'remote',
      reference_value: 'https://example.com/template.json',
    }),
    'custom · 远程模板 · file=https://example.com/template.json'
  );
});

function createClassList(initial = []) {
  const classes = new Set(initial);
  return {
    add(...names) {
      names.forEach((name) => classes.add(name));
    },
    remove(...names) {
      names.forEach((name) => classes.delete(name));
    },
    contains(name) {
      return classes.has(name);
    },
  };
}

function createElement({ value = '', textContent = '', hidden = false } = {}) {
  return {
    value,
    textContent,
    className: '',
    disabled: false,
    style: {},
    classList: createClassList(hidden ? ['hidden'] : []),
    _innerHTML: '',
    get innerHTML() {
      return this._innerHTML;
    },
    set innerHTML(value) {
      this._innerHTML = String(value);
    },
  };
}

function loadSubscriptionUiGlobals({ fetchResponses }) {
  const html = readHtml();
  const script = [
    "let currentSubContent = '';",
    "let currentSubscriptionLink = '';",
    'let currentSubTemplates = [];',
    [
      'getSubPayloadFromInputs',
      'formatTemplateBadgeText',
      'loadSubTemplates',
      'updateSubTemplateCard',
      'clearSubResultState',
      'convertSubscription',
      'displaySubResult',
      'updateSubLineNumbers',
    ].map((name) => extractNamedFunctionSource(html, name)).join('\n\n'),
  ].join('\n\n');

  const elements = {
    'sub-url': createElement({ value: ' https://example.com/subscription ' }),
    'sub-template': createElement(),
    'sub-template-card': createElement({ hidden: true }),
    'sub-template-badge': createElement(),
    'sub-template-description': createElement(),
    'sub-convert-btn': createElement(),
    'sub-error': createElement({ hidden: true }),
    'sub-proxies-section': createElement({ hidden: true }),
    'sub-proxies-list': createElement(),
    'sub-proxies-count': createElement(),
    'sub-output-section': createElement({ hidden: true }),
    'sub-output-text': createElement(),
    'sub-output-title': createElement(),
    'sub-link': createElement(),
    'sub-template-result': createElement({ hidden: true }),
    'sub-template-result-text': createElement(),
    'sub-line-numbers': createElement(),
  };
  const calls = [];
  const toastMessages = [];
  const responses = [...fetchResponses];

  const context = {
    globalThis: {},
    document: {
      getElementById(id) {
        return elements[id] ?? null;
      },
    },
    window: {
      location: {
        origin: 'https://tools.example',
      },
    },
    fetch: async (url, options = {}) => {
      calls.push({ url, options });
      const response = responses.shift();
      assert.ok(response, `Unexpected fetch call to ${url}`);
      return {
        ok: response.ok ?? true,
        status: response.status ?? 200,
        json: async () => response.body,
      };
    },
    showToast: (message, type = 'error') => {
      toastMessages.push({ message, type });
    },
    escapeHtml: (value) => String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;'),
    hljs: {
      highlightElement(element) {
        element.highlighted = true;
      },
    },
    JSON,
    Error,
    console,
  };

  vm.createContext(context);
  vm.runInContext(
    `${script}; globalThis.__loaded = {
      loadSubTemplates,
      convertSubscription,
      get currentSubContent() { return currentSubContent; },
      get currentSubscriptionLink() { return currentSubscriptionLink; },
      get currentSubTemplates() { return currentSubTemplates; },
    };`,
    context
  );

  const loaded = context.globalThis.__loaded;
  return {
    loadSubTemplates: loaded.loadSubTemplates,
    convertSubscription: loaded.convertSubscription,
    get currentSubContent() { return loaded.currentSubContent; },
    get currentSubscriptionLink() { return loaded.currentSubscriptionLink; },
    get currentSubTemplates() { return loaded.currentSubTemplates; },
    calls,
    elements,
    toastMessages,
  };
}

test('subscription UI loads templates, converts, then clears stale result on failure', async () => {
  const ui = loadSubscriptionUiGlobals({
    fetchResponses: [
      {
        body: [
          {
            name: 'Default sing-box',
            reference_key: 'sb-config-1.14',
            reference_value: 'builtin/sb-config-1.14.json',
            source: 'builtin',
            description: 'Default template',
          },
          {
            name: 'Remote template',
            reference_key: 'remote-template',
            reference_value: 'https://example.com/template.json',
            source: 'remote',
            description: 'Remote template description',
          },
        ],
      },
      {
        body: {
          success: true,
          format: 'singbox',
          code_class: 'language-json',
          preview_content: '{"outbounds":[{"tag":"proxy"}]}',
          subscription_path: '/api/sub/download/abc',
          proxies: [
            { name: 'Proxy 1', protocol: 'vmess', server: 'server.example', port: 443 },
          ],
          template_info: {
            name: 'Remote template',
            reference_value: 'https://example.com/template.json',
            source: 'remote',
          },
        },
      },
      {
        body: {
          success: false,
          error: 'invalid subscription',
        },
      },
    ],
  });

  await ui.loadSubTemplates();

  assert.equal(ui.calls[0].url, '/api/sub/templates');
  assert.match(ui.elements['sub-template'].innerHTML, /value="sb-config-1\.14"/);
  assert.match(ui.elements['sub-template'].innerHTML, /value="remote-template"/);
  assert.equal(ui.elements['sub-template'].value, 'sb-config-1.14');
  assert.equal(ui.elements['sub-template-card'].classList.contains('hidden'), false);

  ui.elements['sub-template'].value = 'remote-template';
  await ui.convertSubscription();

  assert.equal(ui.calls[1].url, '/api/sub/convert');
  assert.equal(ui.calls[1].options.method, 'POST');
  assert.equal(ui.calls[1].options.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(ui.calls[1].options.body), {
    subscription_url: 'https://example.com/subscription',
    template: 'remote-template',
    file: 'remote-template',
  });
  assert.equal(ui.currentSubContent, '{"outbounds":[{"tag":"proxy"}]}');
  assert.equal(ui.currentSubscriptionLink, 'https://tools.example/api/sub/download/abc');
  assert.equal(ui.elements['sub-output-section'].classList.contains('hidden'), false);
  assert.equal(ui.elements['sub-proxies-section'].classList.contains('hidden'), false);
  assert.equal(ui.elements['sub-template-result'].classList.contains('hidden'), false);
  assert.equal(ui.elements['sub-output-text'].textContent, '{"outbounds":[{"tag":"proxy"}]}');
  assert.equal(ui.elements['sub-link'].textContent, 'https://tools.example/api/sub/download/abc');
  assert.equal(
    ui.elements['sub-template-result-text'].textContent,
    'Remote template · 远程模板 · file=https://example.com/template.json'
  );

  await ui.convertSubscription();

  assert.equal(ui.elements['sub-error'].textContent, 'invalid subscription');
  assert.equal(ui.elements['sub-error'].classList.contains('hidden'), false);
  assert.equal(ui.elements['sub-output-section'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-proxies-section'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-template-result'].classList.contains('hidden'), true);
  assert.equal(ui.currentSubContent, '');
  assert.equal(ui.currentSubscriptionLink, '');
  assert.equal(ui.elements['sub-output-text'].textContent, '');
  assert.equal(ui.elements['sub-link'].textContent, '');
  assert.equal(ui.elements['sub-template-result-text'].textContent, '');
});

test('subscription UI clears stale result when converting with an empty URL', async () => {
  const ui = loadSubscriptionUiGlobals({
    fetchResponses: [
      {
        body: {
          success: true,
          format: 'singbox',
          code_class: 'language-json',
          preview_content: '{"outbounds":[{"tag":"proxy"}]}',
          subscription_path: '/api/sub/download/abc',
          proxies: [
            { name: 'Proxy 1', protocol: 'vmess', server: 'server.example', port: 443 },
          ],
          template_info: {
            name: 'Remote template',
            reference_value: 'https://example.com/template.json',
            source: 'remote',
          },
        },
      },
    ],
  });

  ui.elements['sub-template'].value = 'remote-template';
  await ui.convertSubscription();

  assert.equal(ui.calls.length, 1);
  assert.equal(ui.currentSubContent, '{"outbounds":[{"tag":"proxy"}]}');
  assert.equal(ui.currentSubscriptionLink, 'https://tools.example/api/sub/download/abc');
  assert.equal(ui.elements['sub-output-section'].classList.contains('hidden'), false);
  assert.equal(ui.elements['sub-proxies-section'].classList.contains('hidden'), false);
  assert.equal(ui.elements['sub-template-result'].classList.contains('hidden'), false);

  ui.elements['sub-error'].textContent = 'stale subscription error';
  ui.elements['sub-error'].classList.remove('hidden');
  assert.equal(ui.elements['sub-error'].classList.contains('hidden'), false);

  ui.elements['sub-url'].value = '   ';
  await ui.convertSubscription();

  assert.equal(ui.calls.length, 1);
  assert.equal(ui.elements['sub-error'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-output-section'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-proxies-section'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-template-result'].classList.contains('hidden'), true);
  assert.equal(ui.currentSubContent, '');
  assert.equal(ui.currentSubscriptionLink, '');
  assert.equal(ui.elements['sub-output-text'].textContent, '');
  assert.equal(ui.elements['sub-link'].textContent, '');
  assert.equal(ui.elements['sub-template-result-text'].textContent, '');
  assert.ok(ui.toastMessages.some(({ message }) => message === '请输入订阅链接'));
});
