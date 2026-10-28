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

function loadSubscriptionGlobals({ subscriptionUrl = 'https://example.com/sub', template = 'singbox', sourceType = 'url', subscriptionContent = '' } = {}) {
  const html = readHtml();
  const script = ['getSubPayloadFromInputs', 'formatTemplateBadgeText']
    .map((name) => extractNamedFunctionSource(html, name))
    .join('\n\n');

  const elements = {
    'sub-source-type': { value: sourceType },
    'sub-content': { value: subscriptionContent },
    'sub-url': { value: subscriptionUrl },
    'sub-template': { value: template },
    'sub-ua': { value: 'surge' },
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

test('getSubPayloadFromInputs sends the unchanged subscription URL and selected User-Agent', () => {
  const { getSubPayloadFromInputs } = loadSubscriptionGlobals({
    subscriptionUrl: ' https://example.com/subscription ',
    template: '5',
  });

  assert.deepEqual(JSON.parse(JSON.stringify(getSubPayloadFromInputs())), {
    subscription_url: 'https://example.com/subscription',
    template: '5',
    file: '5',
    ua: 'surge',
  });
});

test('getSubPayloadFromInputs sends only pasted content and template in content mode', () => {
  const { getSubPayloadFromInputs } = loadSubscriptionGlobals({
    sourceType: 'content',
    subscriptionContent: ' trojan://secret@proxy.example.com:443#node\n ',
    template: '1',
  });
  assert.deepEqual(JSON.parse(JSON.stringify(getSubPayloadFromInputs())), {
    subscription_content: 'trojan://secret@proxy.example.com:443#node',
    template: '1',
    file: '1',
  });
});

test('formatTemplateBadgeText labels builtin templates', () => {
  const { formatTemplateBadgeText } = loadSubscriptionGlobals();

  assert.equal(
    formatTemplateBadgeText({
      name: 'default',
      source: 'builtin',
      reference_value: '1',
    }),
    'default · 内置模板 · file=1'
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
    toggle(name, force) {
      const enabled = force ?? !classes.has(name);
      if (enabled) classes.add(name);
      else classes.delete(name);
      return enabled;
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
      'updateSubSourceType',
      'formatTemplateBadgeText',
      'loadSubTemplates',
      'updateSubTemplateCard',
      'clearSubResultState',
      'convertSubscription',
      'displaySubResult',
      'updateSubLineNumbers',
      'downloadSubJson',
    ].map((name) => extractNamedFunctionSource(html, name)).join('\n\n'),
  ].join('\n\n');

  const elements = {
    'sub-source-type': createElement({ value: 'url' }),
    'sub-content': createElement(),
    'sub-content-input': createElement({ hidden: true }),
    'sub-url-input': createElement(),
    'sub-url-options': createElement(),
    'sub-url': createElement({ value: ' https://example.com/subscription ' }),
    'sub-ua': createElement({ value: 'clashmeta' }),
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
    'sub-link-section': createElement({ hidden: true }),
    'sub-copy-link-btn': createElement({ hidden: true }),
    'sub-validation': createElement({ hidden: true }),
    'sub-template-result': createElement({ hidden: true }),
    'sub-template-result-text': createElement(),
    'sub-line-numbers': createElement(),
  };
  const calls = [];
  const downloads = [];
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
        json: async () => {
          if (response.invalidJson) throw new SyntaxError('Unexpected token <');
          return response.body;
        },
      };
    },
    showToast: (message, type = 'error') => {
      toastMessages.push({ message, type });
    },
    downloadFile: (filename, content, type) => {
      downloads.push({ filename, content, type });
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
      updateSubSourceType,
      convertSubscription,
      downloadSubJson,
      get currentSubContent() { return currentSubContent; },
      get currentSubscriptionLink() { return currentSubscriptionLink; },
      get currentSubTemplates() { return currentSubTemplates; },
    };`,
    context
  );

  const loaded = context.globalThis.__loaded;
  return {
    loadSubTemplates: loaded.loadSubTemplates,
    updateSubSourceType: loaded.updateSubSourceType,
    convertSubscription: loaded.convertSubscription,
    downloadSubJson: loaded.downloadSubJson,
    get currentSubContent() { return loaded.currentSubContent; },
    get currentSubscriptionLink() { return loaded.currentSubscriptionLink; },
    get currentSubTemplates() { return loaded.currentSubTemplates; },
    calls,
    downloads,
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
            reference_key: 'config_template_groups_rule_set_tun',
            reference_value: '1',
            index: 1,
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
  assert.match(ui.elements['sub-template'].innerHTML, /value="1"/);
  assert.match(ui.elements['sub-template'].innerHTML, /value="remote-template"/);
  assert.equal(ui.elements['sub-template'].value, '1');
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
    ua: 'clashmeta',
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

  ui.downloadSubJson();
  assert.deepEqual(ui.downloads, [
    {
      filename: 'sing-box-config.json',
      content: '{"outbounds":[{"tag":"proxy"}]}',
      type: 'application/json',
    },
  ]);
  assert.ok(ui.toastMessages.some(({ message, type }) => message === 'JSON 已下载' && type === 'success'));

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
  assert.equal(ui.elements['sub-error'].classList.contains('hidden'), false);
  assert.equal(ui.elements['sub-error'].textContent, '请输入订阅链接');
  assert.equal(ui.elements['sub-output-section'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-proxies-section'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-template-result'].classList.contains('hidden'), true);
  assert.equal(ui.currentSubContent, '');
  assert.equal(ui.currentSubscriptionLink, '');
  assert.equal(ui.elements['sub-output-text'].textContent, '');
  assert.equal(ui.elements['sub-link'].textContent, '');
  assert.equal(ui.elements['sub-template-result-text'].textContent, '');
  assert.equal(ui.elements['sub-validation'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-validation'].textContent, '');
});

test('subscription content mode hides URL settings and submits pasted content without publishing a link', async () => {
  const ui = loadSubscriptionUiGlobals({ fetchResponses: [{ body: {
    success: true,
    format: 'singbox',
    preview_content: '{"outbounds":[]}',
    subscription_path: null,
    proxies: [{ name: 'node', protocol: '<img onerror=alert(1)>', server: 'proxy.example.com', port: 443 }],
    validation: { engine: 'sing-box', version: '1.14.4', checked: true },
  } }] });
  ui.elements['sub-source-type'].value = 'content';
  ui.elements['sub-content'].value = ' trojan://secret@proxy.example.com:443#node ';
  ui.elements['sub-template'].value = '1';
  ui.updateSubSourceType();
  assert.equal(ui.elements['sub-url-input'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-url-options'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-content-input'].classList.contains('hidden'), false);
  await ui.convertSubscription();
  assert.deepEqual(JSON.parse(ui.calls[0].options.body), {
    subscription_content: 'trojan://secret@proxy.example.com:443#node', template: '1', file: '1',
  });
  assert.equal(ui.currentSubscriptionLink, '');
  assert.equal(ui.elements['sub-link-section'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-copy-link-btn'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-output-section'].classList.contains('hidden'), false);
  assert.equal(ui.elements['sub-validation'].classList.contains('hidden'), false);
  assert.match(ui.elements['sub-validation'].textContent, /sing-box 1\.14\.4 内核配置校验通过/);
  assert.match(ui.elements['sub-validation'].textContent, /配置校验通过不代表节点连通/);
  assert.match(ui.elements['sub-proxies-list'].innerHTML, /&lt;img onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(ui.elements['sub-proxies-list'].innerHTML, /<img/);
  ui.downloadSubJson();
  assert.equal(ui.downloads[0].content, '{"outbounds":[]}');
  ui.elements['sub-source-type'].value = 'url';
  ui.updateSubSourceType();
  assert.equal(ui.elements['sub-url-input'].classList.contains('hidden'), false);
  assert.equal(ui.elements['sub-url-options'].classList.contains('hidden'), false);
  assert.equal(ui.elements['sub-content-input'].classList.contains('hidden'), true);
  assert.equal(ui.currentSubContent, '');
});

test('empty pasted content shows a persistent error without making a request', async () => {
  const ui = loadSubscriptionUiGlobals({ fetchResponses: [] });
  ui.elements['sub-source-type'].value = 'content';
  ui.elements['sub-content'].value = ' \n ';
  await ui.convertSubscription();
  assert.equal(ui.calls.length, 0);
  assert.equal(ui.elements['sub-error'].classList.contains('hidden'), false);
  assert.equal(ui.elements['sub-error'].textContent, '请粘贴原始订阅内容');
});

test('non-JSON HTTP errors are shown persistently and clear the previous successful result', async () => {
  const ui = loadSubscriptionUiGlobals({ fetchResponses: [
    { body: { success: true, format: 'singbox', preview_content: '{}', subscription_path: '/api/sub/config/abc', validation: { version: '1.14.4', checked: true } } },
    { ok: false, status: 502, invalidJson: true },
  ] });
  await ui.convertSubscription();
  assert.equal(ui.elements['sub-copy-link-btn'].classList.contains('hidden'), false);
  assert.equal(ui.elements['sub-link-section'].classList.contains('hidden'), false);
  await ui.convertSubscription();
  assert.equal(ui.currentSubContent, '');
  assert.equal(ui.currentSubscriptionLink, '');
  assert.equal(ui.elements['sub-output-section'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-validation'].classList.contains('hidden'), true);
  assert.equal(ui.elements['sub-error'].classList.contains('hidden'), false);
  assert.match(ui.elements['sub-error'].textContent, /非 JSON 响应（HTTP 502）/);
  assert.equal(ui.elements['sub-convert-btn'].disabled, false);
});

test('JSON HTTP errors preserve backend explanations including unavailable validation engines', async () => {
  const ui = loadSubscriptionUiGlobals({ fetchResponses: [{ ok: false, status: 503, body: { success: false, error: '未找到 sing-box 内核，请设置 SING_BOX_BINARY' } }] });
  await ui.convertSubscription();
  assert.equal(ui.elements['sub-error'].textContent, '未找到 sing-box 内核，请设置 SING_BOX_BINARY');
  assert.equal(ui.elements['sub-error'].classList.contains('hidden'), false);
  assert.equal(ui.elements['sub-output-section'].classList.contains('hidden'), true);
});

test('template loading chooses the recommended template before the first indexed template', async () => {
  const ui = loadSubscriptionUiGlobals({ fetchResponses: [{ body: [
    { name: 'Other', index: 1, reference_key: 'other', source: 'builtin' },
    { name: 'Recommended', index: 2, reference_key: 'recommended', source: 'builtin', recommended: true, sing_box_version: '1.14.x' },
  ] }] });
  await ui.loadSubTemplates();
  assert.equal(ui.elements['sub-template'].value, '2');
  assert.match(ui.elements['sub-template-badge'].textContent, /sing-box 1\.14\.x/);
});
