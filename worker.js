/**
 * worker.js - 强化版（完整、健壮、多 host 支持，优化缓存与容错）
 *
 * 功能要点回顾：
 *  - 把 *.wikipedia.org/*.wikimedia.org 的链接改写成
 *      https://替换为自己的域名/__proxy__/{host}{path}
 *    Worker 处理 /__proxy__/* 并转发到对应 host。
 *  - HTML 使用 HTMLRewriter 最小改写（包含 srcset、data-srcset、style:url() 等）。
 *  - 静态资源走边缘缓存（caches.default + cf.cacheEverything），HTML 短缓存。
 *  - 处理 Range、Referer、User-Agent，删除限制性响应头（CSP/COOP/CORP/X-Frame-Options 等）。
 *  - 当 proxied 请求失败时，尝试回退到直接请求上游原始 URL（作为最后手段）。
 *  - 基本方法白名单、简易本地失效缓存、友好错误页。
 *  - 独立密钥登录页，使用签名 Cookie 保护整个代理。
 *
 * 请结合 Cloudflare 仪表盘的 DNS/Routes/Edge Certificates 配置使用（CNAME -> workers.dev，橙云开启）。
 */


const PROXY_PASSWORD = '你的密码';        // 替换成你想要的密码
const PROXY_HOST = '你自己的域名';        // 替换成你部署的域名（必须是 CF Worker 绑定的域名）    
const DEFAULT_ORIGIN = 'zh.wikipedia.org';
// 统一用 punycode 形式拼接链接：填中文域名也能正常工作，ASCII 形式在 HTML/CSS/命令行里更稳
const PROXY_HOST_ASCII = (() => {
  try { return new URL('https://' + PROXY_HOST).hostname; } catch (e) { return PROXY_HOST; }
})();
const PROXY_PREFIX = '/__proxy__/';
const LOGIN_PATH = '/__wiki_login';
const SESSION_COOKIE = 'wiki_proxy_session';
const SESSION_TTL = 60 * 60 * 24 * 7;

// 缓存与性能调优（按需调整）
const TTL_HTML = 60 * 60 * 12;           // HTML 缓存 12 小时
const TTL_ASSET_SHORT = 60 * 60 * 12; // 静态资源短缓存 12 小时
const TTL_ASSET_LONG = 60 * 60 * 24 * 30; // 静态资源长缓存 30 天
const CACHE_VERSION = 'v3';               // 部署新版本时改一下：旧 HTML 边缘缓存会自动失配

// ---- 资源合并 / 请求数优化 ----
const INLINE_CSS = true;                   // 把外链样式表内联进 HTML，省掉每个 CSS 的独立请求
const MAX_INLINE_CSS_BYTES = 400 * 1024;   // 单个 CSS 超过该体积则不内联（避免 HTML 过大）
const INLINE_ASSET_LIMIT = 32 * 1024;      // CSS 内引用的小字体/图标内联为 data URI（0 = 关闭）
const INLINE_FAVICON = true;               // 站点图标内联为 data URI
const MAX_INLINE_ASSETS_PER_PAGE = 6;      // 每页最多内联几个字体/图标（防止子请求数失控）
const UPSTREAM_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36';
// 统一的边缘缓存键请求头：避免 Cookie / Accept 差异或上游 Vary 导致缓存永远不命中
const CACHE_KEY_HEADERS = { 'Accept-Encoding': 'gzip, br' };


// 允许的方法
const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST', 'OPTIONS']);

// 简易内存失败缓存（仅在当前 Worker 实例存活期间有效）
const hostFailureMap = new Map(); // host -> timestamp of last failure

// 多久认为 host 恢复？（秒）
const HOST_FAILURE_TTL = 60 * 60; // 1 hour

// ES Module 格式：rate limiting binding 需要它（Service Worker 格式会导致 workerd 启动失败）
export default {
  async fetch(request, env) {
    return await mainHandler(request, env);
  }
};

/* ========== 登录与会话验证 ========== */
async function authenticate(request) {
  const cookies = request.headers.get('Cookie') || '';
  const match = cookies.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`));
  if (!match) return false;

  const token = decodeURIComponent(match[1]);
  const parts = token.split('.');
  if (parts.length !== 2 || !/^\d+$/.test(parts[0])) return false;

  const issuedAt = Number(parts[0]);
  if (!Number.isSafeInteger(issuedAt) || Math.floor(Date.now() / 1000) - issuedAt > SESSION_TTL) {
    return false;
  }

  return parts[1] === await signSession(parts[0]);
}

async function signSession(value) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(PROXY_PASSWORD),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value));
  return [...new Uint8Array(signature)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function loginPage(message = '', next = '/') {
  const safeMessage = String(message).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const safeNext = next.startsWith('/') && !next.startsWith('//') ? next : '/';
  const action = `${LOGIN_PATH}?next=${encodeURIComponent(safeNext)}`;
  return new Response(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>访问验证</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f5f7fb;color:#222}
form{box-sizing:border-box;width:min(360px,calc(100% - 32px));padding:28px;background:#fff;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.08)}
h1{margin:0 0 20px;font-size:22px;text-align:center}label{display:block;margin-bottom:8px;font-size:14px}input{box-sizing:border-box;width:100%;padding:11px 12px;border:1px solid #ccd3dd;border-radius:6px;font-size:16px}button{width:100%;margin-top:16px;padding:11px;border:0;border-radius:6px;background:#1769aa;color:#fff;font-size:16px;cursor:pointer}.error{margin:0 0 12px;color:#c0392b;font-size:14px;text-align:center}
</style></head><body><form method="post" action="${action}"><h1>访问验证</h1>${safeMessage ? `<p class="error">${safeMessage}</p>` : ''}<label for="key">请输入访问密钥</label><input id="key" name="key" type="password" autocomplete="current-password" required autofocus><button type="submit">进入网站</button></form></body></html>`, {
    status: message ? 401 : 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

async function handleLogin(request, url) {
  if (request.method === 'GET') return loginPage();
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

  let form;
  try {
    form = await request.formData();
  } catch (e) {
    return loginPage('请求格式无效');
  }

  if (form.get('key') !== PROXY_PASSWORD) return loginPage('密钥错误，请重试');

  const issuedAt = String(Math.floor(Date.now() / 1000));
  const token = `${issuedAt}.${await signSession(issuedAt)}`;
  const next = url.searchParams.get('next');
  const location = next && next.startsWith('/') && !next.startsWith('//') ? next : '/';
  return new Response(null, {
    status: 303,
    headers: {
      Location: location,
      'Set-Cookie': `${SESSION_COOKIE}=${encodeURIComponent(token)}; Max-Age=${SESSION_TTL}; Path=/; Secure; HttpOnly; SameSite=Lax`,
      'Cache-Control': 'no-store'
    }
  });
}

/* -------------------- 主入口 -------------------- */
async function mainHandler(request, env) {
  try {
    const url = new URL(request.url);


    if (url.pathname === LOGIN_PATH) return await handleLogin(request, url);

    if (!(await authenticate(request))) {
      return loginPage('', url.pathname + url.search);
    }

    // 方法限制
    if (!ALLOWED_METHODS.has(request.method)) {
      return new Response('Method Not Allowed', { status: 405 });
    }

    // health check
    if (url.pathname === '/__wiki_proxy_ping') return new Response('ok', { status: 200 });

    // If proxy prefix, forward to specific upstream host
    if (url.pathname.startsWith(PROXY_PREFIX)) {
      return await handleProxyUpstream(request, url);
    }

    // Otherwise handle site request (html vs static)
    return await handleSiteRequest(request, url);

  } catch (err) {
    // Unexpected error -> return friendly page
    return errorPage('Unexpected server error: ' + (err && err.message ? err.message : String(err)));
  }
}

/* -------------------- proxy upstream (/__proxy__/host/...) -------------------- */
async function handleProxyUpstream(request, url) {
  // e.g. /__proxy__/upload.wikimedia.org/wikipedia/commons/...
  try {
    const parts = url.pathname.split('/').filter(Boolean);
    if (parts.length < 2 || parts[0] !== '__proxy__') {
      return new Response('Bad proxy path', { status: 400 });
    }

    const hostname = parts[1];
    // Basic safety: hostname must look like a host (letters, digits, dots, hyphens)
    if (!/^[a-z0-9.-]+$/i.test(hostname)) {
      return new Response('Invalid host in proxy path', { status: 400 });
    }

    const path = '/' + parts.slice(2).join('/');
    const target = `https://${hostname}${path}${url.search}`;

    // If this host has a recent failure, fail fast to avoid wasted fetches
    if (isHostRecentlyFailed(hostname)) {
      return errorPage(`Upstream host ${hostname} recently returned errors; try again later.`);
    }

    const likelyAsset = isLikelyAsset(path);

    // Build forwarded request (preserve method/body for POST)
    const forwardedReq = new Request(target, {
      method: request.method,
      // 静态资源不转发 Cookie：避免上游返回私有/个性化响应，也让边缘缓存更容易命中
      headers: prepareForwardHeaders(request.headers, hostname, { stripCookies: likelyAsset }),
      body: request.method === 'GET' || request.method === 'HEAD' ? null : request.body,
      redirect: 'follow'
    });

    const cache = caches.default;
    // 缓存键固定为一组最小请求头，避免 Cookie / Accept 差异或上游 Vary 让缓存永不命中
    const cacheKey = new Request(target, { method: 'GET', headers: CACHE_KEY_HEADERS });

    // For assets try edge cache first
    if (likelyAsset) {
      try {
        const cached = await cache.match(cacheKey);
        if (cached) return cached;
      } catch (e) { /* ignore cache errors */ }
    }

    // Use CF caching hints to keep things in edge
    const cfOptions = { cacheTtl: likelyAsset ? TTL_ASSET_LONG : TTL_ASSET_SHORT, cacheEverything: true };

    let fetched;
    try {
      fetched = await fetch(forwardedReq, { cf: cfOptions });
    } catch (err) {
      // mark host as failing
      markHostFailure(hostname);
      // try fallback: attempt direct fetch without our forwarded headers
      try {
        fetched = await fetch(target);
      } catch (err2) {
        markHostFailure(hostname);
        return errorPage(`Failed to fetch upstream ${hostname}: ${err2.message}`);
      }
    }

    // If upstream returned error status, mark and maybe fallback
    if (fetched.status >= 500) {
      markHostFailure(hostname);
    }

    // Clean problematic headers (CSP etc.)
    const cleanedHeaders = stripProblematicHeaders(fetched.headers);

    // Support Range requests: if origin returned 206/200, pass through
    const resp = new Response(fetched.body, {
      status: fetched.status,
      statusText: fetched.statusText,
      headers: cleanedHeaders
    });

    // Set Cache-Control for edge/downstream for successful static assets
    if (fetched.status === 200 && likelyAsset) {
      resp.headers.set('Cache-Control', `public, max-age=${TTL_ASSET_LONG}`);
      // 去掉 Set-Cookie / Vary 后再写入，否则 put 会失败或之后永远匹配不上
      eventualCachePut(cache, cacheKey, makeCacheable(resp.clone(), TTL_ASSET_LONG)).catch(()=>{});
    } else if (fetched.status === 200) {
      resp.headers.set('Cache-Control', `public, max-age=${TTL_ASSET_SHORT}`);
    }

    // Add a tiny debug header (remove in production if you like)
    resp.headers.set('X-VPNWiki-Proxy', 'upstream');

    return resp;

  } catch (err) {
    return errorPage('Proxy upstream handler error: ' + (err.message || String(err)));
  }
}

/* -------------------- site request handling (HTML rewriting vs static) -------------------- */
async function handleSiteRequest(request, url) {
  const cache = caches.default;
  const accept = (request.headers.get('Accept') || '').toLowerCase();
  const acceptsHtml = accept.includes('text/html');
  const likelyAsset = isLikelyAsset(url.pathname);

  // Treat as static asset if extension or client doesn't accept HTML
  if (likelyAsset || !acceptsHtml) {
    return await fetchAndCacheOrigin(request, url, { asset: true });
  }

  // For HTML pages: try edge cache for rewritten HTML
  // key 带缓存版本号：部署新版本后旧 HTML 缓存自动失配，不用等 TTL 过期
  const cacheKey = new Request(`${request.url}${url.search ? '&' : '?'}__cv=${CACHE_VERSION}`, { method: 'GET' });
  try {
    const cached = await cache.match(cacheKey);
    if (cached) return cached;
  } catch (e) { /* ignore */ }

  // Compose origin URL (page) on DEFAULT_ORIGIN
  const originUrl = `https://${DEFAULT_ORIGIN}${url.pathname}${url.search}`;
  const forwarded = new Request(originUrl, {
    method: request.method,
    headers: prepareForwardHeaders(request.headers, DEFAULT_ORIGIN),
    body: request.method === 'GET' || request.method === 'HEAD' ? null : request.body,
    // 重定向交给浏览器处理：否则地址栏停留在旧路径，页面内相对资源会全部错位
    redirect: 'manual'
  });

  let fetched;
  try {
    fetched = await fetch(forwarded, { cf: { cacheTtl: TTL_HTML, cacheEverything: true } });
  } catch (err) {
    return errorPage('Failed to fetch origin HTML: ' + (err.message || String(err)));
  }

  // 上游 3xx：改写成代理地址后返回给浏览器，保证地址栏与实际内容一致
  if (isRedirectStatus(fetched.status)) {
    const proxyLocation = toProxyLocation(fetched.headers.get('location'), originUrl);
    if (proxyLocation) {
      return new Response(null, {
        status: fetched.status,
        headers: { location: proxyLocation, 'cache-control': 'no-store' }
      });
    }
  }

  const contentType = (fetched.headers.get('content-type') || '').toLowerCase();
  if (!contentType.includes('text/html')) {
    // Not HTML — pass through cleaned headers
    return new Response(fetched.body, {
      status: fetched.status,
      statusText: fetched.statusText,
      headers: stripProblematicHeaders(fetched.headers)
    });
  }

  // HTML: 先把样式表内容合并进文档（纯文本替换，稳定且可并行 fetch），再交给 HTMLRewriter 改写 URL
  const documentBase = fetched.url || originUrl;
  const sourceHtml = await fetched.text();
  const mergedHtml = await inlineStylesheets(patchMwConfig(sourceHtml), documentBase);

  const rewriter = new HTMLRewriter()
    .on('a', new AttrRewriter('href', documentBase))
    .on('link', new AttrRewriter('href', documentBase))
    .on('script', new AttrRewriter('src', documentBase))
    .on('img', new AttrRewriter('src', documentBase))
    .on('img', new AttrRewriter('srcset', documentBase))
    .on('img', new AttrRewriter('data-src', documentBase))
    .on('img', new AttrRewriter('data-srcset', documentBase))
    .on('source', new AttrRewriter('src', documentBase))
    .on('source', new AttrRewriter('srcset', documentBase))
    .on('video', new AttrRewriter('src', documentBase))
    .on('video', new AttrRewriter('poster', documentBase))
    .on('audio', new AttrRewriter('src', documentBase))
    .on('form', new AttrRewriter('action', documentBase))
    .on('*', new StyleAttrRewriter(documentBase));

  const transformed = rewriter.transform(new Response(mergedHtml, {
    status: 200,
    headers: { 'content-type': 'text/html; charset=utf-8' }
  }));

  const finalResp = new Response(transformed.body, {
    status: fetched.status,
    statusText: fetched.statusText,
    // body 已被重新生成，必须丢掉 content-encoding/content-length 等旧头
    headers: stripBodyHeaders(fetched.headers)
  });

  // Cache rewritten HTML
  if (finalResp.status === 200) {
    // 浏览器与边缘统一按 TTL_HTML 缓存，尽量少回源
    finalResp.headers.set('Cache-Control', `public, max-age=${TTL_HTML}`);
    try { await cache.put(cacheKey, makeCacheable(finalResp.clone(), TTL_HTML)); } catch (e) { /* ignore */ }
  }

  finalResp.headers.set('X-VPNWiki-Proxy', 'html-rewritten');
  return finalResp;
}

/* -------------------- fetch origin & cache (for default origin) -------------------- */
async function fetchAndCacheOrigin(request, url, opts = {}) {
  // opts.asset = boolean
  const cache = caches.default;
  const path = url.pathname + url.search;
  const target = `https://${DEFAULT_ORIGIN}${path}`;

  // For direct asset paths that point to non-default hosts, the HTML rewrite will create /__proxy__/host/... requests.
  const forwarded = new Request(target, {
    method: request.method,
    headers: prepareForwardHeaders(request.headers, DEFAULT_ORIGIN, { stripCookies: !!opts.asset }),
    body: request.method === 'GET' || request.method === 'HEAD' ? null : request.body,
    redirect: 'follow'
  });

  // 缓存键统一为一组最小请求头，避免 Cookie/Accept 差异或上游 Vary 导致永不命中
  const cacheKey = new Request(target, { method: request.method, headers: CACHE_KEY_HEADERS });

  // try cache
  try {
    const cached = await cache.match(cacheKey);
    if (cached) return cached;
  } catch (e) { /* ignore */ }

  try {
    const cfOptions = { cacheTtl: opts.asset ? TTL_ASSET_LONG : TTL_ASSET_SHORT, cacheEverything: true };
    const fetched = await fetch(forwarded, { cf: cfOptions });
    const cleanedHeaders = stripProblematicHeaders(fetched.headers);

    const resp = new Response(fetched.body, {
      status: fetched.status,
      statusText: fetched.statusText,
      headers: cleanedHeaders
    });

    if (fetched.status === 200) {
      resp.headers.set('Cache-Control', `public, max-age=${cfOptions.cacheTtl}`);
      eventualCachePut(cache, cacheKey, makeCacheable(resp.clone(), cfOptions.cacheTtl)).catch(()=>{});
    }

    resp.headers.set('X-VPNWiki-Proxy', 'origin-fetch');
    return resp;

  } catch (err) {
    return errorPage('Fetch origin asset failed: ' + (err.message || String(err)));
  }
}

/* -------------------- helpers / rewriters / util -------------------- */

// 判定疑似静态资源（基于扩展名）
function isLikelyAsset(pathname) {
  return /\.(png|jpe?g|gif|webp|svg|ico|css|js|mjs|woff2?|ttf|otf|map|mp4|webm|ogg|mp3|wav|flac|m4a|ogv|ogm)(\?.*)?$/i.test(pathname);
}

/* -------------------- 资源合并：内联 CSS / 小资源 data URI -------------------- */

function isProxyableHost(hostname) {
  const host = String(hostname || '').toLowerCase();
  return host === DEFAULT_ORIGIN || host.endsWith('.wikipedia.org') || host.endsWith('.wikimedia.org');
}

function toProxyUrl(absUrl) {
  const host = absUrl.hostname.toLowerCase();
  if (host === DEFAULT_ORIGIN) {
    return `https://${PROXY_HOST_ASCII}${absUrl.pathname}${absUrl.search || ''}`;
  }
  return `https://${PROXY_HOST_ASCII}${PROXY_PREFIX}${host}${absUrl.pathname}${absUrl.search || ''}`;
}

// 读取上游文本资源（CSS），优先命中边缘缓存
async function fetchTextWithCache(target, accept) {
  const cache = caches.default;
  const cacheKey = new Request(target, { method: 'GET', headers: CACHE_KEY_HEADERS });
  try {
    const cached = await cache.match(cacheKey);
    if (cached) return await cached.text();
  } catch (e) { /* ignore */ }

  const res = await fetch(target, {
    headers: { 'User-Agent': UPSTREAM_UA, Accept: accept },
    cf: { cacheTtl: TTL_ASSET_LONG, cacheEverything: true }
  });
  if (!res.ok) return null;

  const text = await res.text();
  try {
    await cache.put(cacheKey, new Response(text, {
      status: 200,
      headers: {
        'content-type': 'text/css; charset=utf-8',
        'cache-control': `public, max-age=${TTL_ASSET_LONG}`
      }
    }));
  } catch (e) { /* ignore */ }
  return text;
}

// 把小的字体/图标读成 data URI；超限或类型不符返回 null
async function fetchAsDataUri(absUrl, limit) {
  try {
    const target = absUrl.toString();
    const cache = caches.default;
    const cacheKey = new Request(target, { method: 'GET', headers: CACHE_KEY_HEADERS });

    let res = null;
    try { res = await cache.match(cacheKey); } catch (e) { /* ignore */ }
    if (!res) {
      res = await fetch(target, {
        headers: { 'User-Agent': UPSTREAM_UA, Accept: '*/*' },
        cf: { cacheTtl: TTL_ASSET_LONG, cacheEverything: true }
      });
      if (!res.ok) return null;
    }

    const type = (res.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    if (!/^(font\/|image\/)/.test(type)) return null;

    const buf = await res.arrayBuffer();
    if (!buf.byteLength || buf.byteLength > limit) return null;

    try {
      await cache.put(cacheKey, new Response(buf, {
        status: 200,
        headers: { 'content-type': type, 'cache-control': `public, max-age=${TTL_ASSET_LONG}` }
      }));
    } catch (e) { /* ignore */ }

    return `data:${type};base64,${arrayBufferToBase64(buf)}`;
  } catch (e) {
    return null;
  }
}

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

// 支持 async 回调的批量替换
async function replaceAsync(input, regex, asyncFn) {
  const matches = [];
  input.replace(regex, (...args) => { matches.push(args); return ''; });
  if (!matches.length) return input;

  const replaced = await Promise.all(matches.map(args => asyncFn(...args)));
  let out = '';
  let last = 0;
  for (let i = 0; i < matches.length; i++) {
    const args = matches[i];
    const full = args[0];
    const offset = args[args.length - 2];
    out += input.slice(last, offset) + replaced[i];
    last = offset + full.length;
  }
  return out + input.slice(last);
}

// 改写 CSS 内 url(...)：小字体转 data URI（受每页额度限制），其余转成代理地址
async function rewriteCssForProxy(css, cssUrl, budget) {
  return await replaceAsync(css, /url\(\s*(['"]?)([^'")]+?)\1\s*\)/gi, async (full, quote, raw) => {
    const ref = String(raw).trim();
    if (!ref || /^(data:|#|about:|blob:|var\()/i.test(ref)) return full;
    let abs;
    try { abs = new URL(ref, cssUrl); } catch (e) { return full; }
    if (!isProxyableHost(abs.hostname)) return full;

    // 只有字体才考虑内联：CSS 里的图标/图片数量可能很多，逐个内联会让子请求数爆炸
    if (INLINE_ASSET_LIMIT > 0 && budget && budget.remaining > 0) {
      if (/\.(woff2?|ttf|otf|eot)(\?.*)?$/i.test(abs.pathname)) {
        budget.remaining--;
        const dataUri = await fetchAsDataUri(abs, INLINE_ASSET_LIMIT);
        if (dataUri) return `url(${quote}${dataUri}${quote})`;
      }
    }
    return `url(${quote}${toProxyUrl(abs)}${quote})`;
  });
}

// 生成可安全写入 caches.default 的响应（带 Set-Cookie/Vary 会导致 put 失败或永不命中）
function makeCacheable(resp, ttl) {
  const headers = new Headers(resp.headers);
  headers.delete('set-cookie');
  headers.delete('vary');
  headers.delete('age');
  headers.set('cache-control', `public, max-age=${ttl}`);
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
}

// 把 mw.config 里的 wgServer 指向代理域名，避免 JS 拼出来的绝对链接直连维基
function patchMwConfig(html) {
  try {
    if (html.indexOf('"wgServer"') === -1) return html;
    return html.replace(/"wgServer":"https?:\/\/[^"]*"/g, `"wgServer":"https://${PROXY_HOST_ASCII}"`);
  } catch (e) {
    return html;
  }
}

/* -------- 文本级合并：把样式表内容并进 HTML，去掉无效预取 -------- */

// 解码 HTML 实体：链接里常见的 &amp; 必须还原成 &，否则 query 参数会全部失效
function decodeEntities(str) {
  if (!str || str.indexOf('&') === -1) return str;
  return str
    .replace(/&#(\d+);/g, (mm, d) => String.fromCharCode(Number(d)))
    .replace(/&#x([0-9a-f]+);/gi, (mm, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&');
}

// 从一个标签字符串里取属性值（并解码实体）
function attrValue(tag, name) {
  const re = new RegExp(`${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, 'i');
  const m = re.exec(tag);
  if (!m) return null;
  return decodeEntities(m[1] !== undefined ? m[1] : (m[2] !== undefined ? m[2] : m[3]));
}

/**
 * 合并样式表 / 内联图标 / 删除无用预取标签。
 * 纯字符串替换：任何异常都原样返回原 HTML，绝不会让页面丢样式。
 */
async function inlineStylesheets(html, documentBase) {
  try {
    if (!INLINE_CSS && !INLINE_FAVICON) return html;

    const tagRe = /<link\b[^>]*>/gi;
    const tags = [];
    let m;
    while ((m = tagRe.exec(html)) !== null) {
      tags.push({ start: m.index, end: m.index + m[0].length, tag: m[0] });
    }
    if (!tags.length) return html;

    const fontBudget = { remaining: MAX_INLINE_ASSETS_PER_PAGE };
    const iconBudget = { remaining: 2 };

    const replaced = await Promise.all(tags.map(async ({ tag }) => {
      const rel = (attrValue(tag, 'rel') || '').toLowerCase();

      // 1) 清掉会产生额外请求的预取标签
      if (/prefetch|prerender/.test(rel)) return '';
      if (rel.includes('preload') && !rel.includes('modulepreload')) {
        const as = (attrValue(tag, 'as') || '').toLowerCase();
        if (as === 'style' || as === 'font' || as === 'fetch') return '';
      }

      const href = attrValue(tag, 'href');
      if (!href) return null;

      let abs;
      try { abs = new URL(href, documentBase); } catch (e) { return null; }
      if (!isProxyableHost(abs.hostname)) return null;

      // 2) 样式表内联
      if (INLINE_CSS && /(^|\s)stylesheet(\s|$)/.test(rel) &&
          !/(^|\s)alternate(\s|$)/.test(rel) && !attrValue(tag, 'title')) {
        const cssText = await fetchTextWithCache(
          `https://${abs.hostname}${abs.pathname}${abs.search}`,
          'text/css,*/*;q=0.1'
        );
        // 上游没拿到有效 CSS 时会返回一段 ResourceLoader 说明文字，绝不能被内联进页面
        const looksPlaceholder = !!cssText && cssText.length < 1000 && /ResourceLoader|This file is the Web entry point/.test(cssText);
        if (cssText && !looksPlaceholder && cssText.length <= MAX_INLINE_CSS_BYTES) {
          const css = (await rewriteCssForProxy(cssText, abs, fontBudget)).replace(/<\/style/gi, '<\\/style');
          const media = attrValue(tag, 'media');
          const mediaAttr = media ? ` media="${media.replace(/"/g, '&quot;')}"` : '';
          return `<style${mediaAttr}>${css}</style>`;
        }
        return null; // 取不到 CSS 就保留 <link>，由 AttrRewriter 改成代理地址
      }

      // 3) 站点图标内联
      if (INLINE_FAVICON && INLINE_ASSET_LIMIT > 0 && iconBudget.remaining > 0 &&
          /(^|\s)(shortcut\s+icon|icon|apple-touch-icon|apple-touch-icon-precomposed|mask-icon)(\s|$)/.test(rel)) {
        iconBudget.remaining--;
        const dataUri = await fetchAsDataUri(abs, INLINE_ASSET_LIMIT);
        if (dataUri) {
          const hrefMatch = tag.match(/href\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'>]+)/i);
          if (hrefMatch) return tag.replace(hrefMatch[0], `href="${dataUri}"`);
        }
      }
      return null;
    }));

    let out = html;
    for (let i = tags.length - 1; i >= 0; i--) {
      const r = replaced[i];
      if (r === null || r === undefined) continue;
      out = out.slice(0, tags[i].start) + r + out.slice(tags[i].end);
    }
    return out;
  } catch (e) {
    return html;
  }
}

// AttrRewriter: 处理 href/src/action 等单 URL 属性，并处理 srcset 的描述符
class AttrRewriter {
  constructor(attrName, documentBase) {
    this.attrName = attrName;
    this.documentBase = documentBase;
  }
  element(el) {
    try {
      const raw = el.getAttribute(this.attrName);
      if (!raw) return;
      if (isAlreadyProxied(raw)) return;

      // srcset / data-srcset: multiple items like "URL 2x, URL2 480w"
      if (this.attrName === 'srcset' || this.attrName === 'data-srcset') {
        const parts = raw.split(',').map(p => p.trim()).filter(Boolean);
        const mapped = parts.map(part => {
          const m = part.match(/^(\S+)(\s+\S+)?$/);
          if (!m) return part;
          const urlPart = m[1];
          const desc = m[2] || '';
          const newUrl = makeProxyUrl(urlPart, this.documentBase);
          return `${newUrl}${desc}`;
        });
        el.setAttribute(this.attrName, mapped.join(', '));
        return;
      }

      // 普通属性：单 url
      const newVal = makeProxyUrl(raw, this.documentBase);
      if (newVal && newVal !== raw) el.setAttribute(this.attrName, newVal);
    } catch (e) {
      // ignore per-element errors
    }
  }
}

// StyleAttrRewriter: 处理内联 style 中的 url(...)
class StyleAttrRewriter {
  constructor(documentBase) { this.documentBase = documentBase; }
  element(el) {
    try {
      const styleVal = el.getAttribute('style');
      if (!styleVal) return;
      const newStyle = styleVal.replace(/url\(\s*(['"]?)(.*?)\1\s*\)/g, (m, q, u) => {
        if (/^(data:|blob:|about:|#)/i.test(u)) return `url(${q}${u}${q})`;
        const newUrl = makeProxyUrl(u, this.documentBase);
        return `url(${q}${newUrl}${q})`;
      });
      if (newStyle !== styleVal) el.setAttribute('style', newStyle);
    } catch (e) {
      // ignore
    }
  }
}

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

function isRedirectStatus(status) {
  return REDIRECT_STATUS.has(status);
}

// 把上游 Location 转成代理地址（主域走干净路径），让浏览器自己跳转
function toProxyLocation(location, upstreamBase) {
  if (!location) return null;
  try {
    const abs = new URL(location, upstreamBase);
    return makeProxyUrl(abs.href, upstreamBase);
  } catch (e) {
    return null;
  }
}

// 判定是否已被改写为我们的 proxy（避免重复改写）
function isAlreadyProxied(val) {
  try {
    if (!val) return false;
    if (typeof val !== 'string') return false;
    if (val.startsWith(PROXY_PREFIX)) return true;
    const u = new URL(val, `https://${DEFAULT_ORIGIN}`);
    if (u.hostname === PROXY_HOST_ASCII) return true;
    if (u.pathname && u.pathname.startsWith(PROXY_PREFIX)) return true;
    return false;
  } catch (e) {
    return false;
  }
}

/**
 * 将任意 URL（相对 / 绝对 / 协议相对）解析并改写为代理路径
 *  - 对 wikipedia.org / wikimedia.org 主机改写
 *  - 对相对路径（解析成 DEFAULT_ORIGIN）也会改写成 /__proxy__/zh.wikipedia.org/...
 */
function makeProxyUrl(orig, documentBase = `https://${DEFAULT_ORIGIN}/`) {
  try {
    if (/^\s*#/.test(orig)) return orig;

    const u = new URL(orig, documentBase); // supports relative and protocol-relative URLs
    const host = u.hostname.toLowerCase();
    // 主站内容用干净路径（/wiki/...、/w/...），和站点入口完全一致
    if (host === DEFAULT_ORIGIN) {
      return `https://${PROXY_HOST_ASCII}${u.pathname}${u.search || ''}${u.hash || ''}`;
    }
    // 其它 wikipedia / wikimedia 子域（upload.wikimedia.org 等）走纯转发通道
    if (host.endsWith('.wikipedia.org') || host.endsWith('.wikimedia.org')) {
      return `https://${PROXY_HOST_ASCII}${PROXY_PREFIX}${host}${u.pathname}${u.search || ''}${u.hash || ''}`;
    }
    // keep third-party absolute URLs unchanged
    return orig;
  } catch (e) {
    return orig;
  }
}

/* 请求头转发准备：转发大部分有用头，但去掉会影响上游识别的 hop-by-hop headers */
function prepareForwardHeaders(originalHeaders, upstreamHost, opts = {}) {
  const headers = new Headers();
  for (const [k, v] of originalHeaders) {
    const key = k.toLowerCase();
    if (['x-forwarded-for','cf-connecting-ip','cf-ray','via','connection','keep-alive','transfer-encoding','upgrade'].includes(key)) continue;
    if (key === 'host') continue;
    // We drop accept-encoding to let Cloudflare manage compression to avoid mismatched encodings
    if (key === 'accept-encoding') continue;
    // 静态资源请求不携带 Cookie：避免上游返回私有响应，也让边缘缓存更容易命中
    if (opts.stripCookies && key === 'cookie') continue;
    headers.set(k, v);
  }
  // set Host to upstreamHost (some origins check Host)
  headers.set('Host', upstreamHost);
  // Prefer to forward client's Referer if present, else use upstream origin as referer
  if (!headers.has('referer') && !headers.has('referrer')) {
    headers.set('Referer', `https://${upstreamHost}/`);
  }
  // Ensure some UA exists
  if (!headers.has('user-agent')) headers.set('User-Agent', 'Mozilla/5.0 (compatible; vpnwiki-proxy/1.0)');
  return headers;
}

/* 删除限制性响应头（CSP、COOP、X-Frame-Options 等）以提高兼容性 */
function stripProblematicHeaders(origHeaders) {
  const headers = new Headers(origHeaders);
  [
    'content-security-policy',
    'content-security-policy-report-only',
    'cross-origin-embedder-policy',
    'cross-origin-opener-policy',
    'cross-origin-resource-policy',
    'x-frame-options'
  ].forEach(h => headers.delete(h));
  return headers;
}

// body 被重新生成后，必须丢掉与旧 body 绑定的头，否则下游会按旧的编码/长度解析
function stripBodyHeaders(origHeaders) {
  const headers = stripProblematicHeaders(origHeaders);
  ['content-encoding', 'content-length', 'transfer-encoding', 'content-md5', 'etag']
    .forEach(h => headers.delete(h));
  return headers;
}

/* 异步向 edge cache 写入，不阻塞主流程 */
async function eventualCachePut(cache, key, value) {
  try {
    await cache.put(key, value);
  } catch (e) {
    // ignore cache put failure
  }
}

/* 错误页面（友好提示） */
function errorPage(message) {
  const safeMsg = String(message).replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const html = `<!doctype html>
  <html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>维基百科代理不可用</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f7fb}
    .box{background:#fff;padding:26px;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,0.08);max-width:720px;text-align:center}
    h1{margin:0 0 12px;color:#c0392b}p{color:#333;line-height:1.6}
    a{color:#0b74de}
  </style></head><body>
    <div class="box">
      <h1>维基百科代理暂时不可用</h1>
      <p>${safeMsg}</p>
      <p>你可以稍后再试，或直接访问源站：<a href="https://zh.wikipedia.org" target="_blank">https://zh.wikipedia.org</a></p>
    </div>
  </body></html>`;
  return new Response(html, { status: 502, headers: { 'content-type': 'text/html; charset=utf-8' } });
}

/* -------------------- host failure cache helpers -------------------- */
function markHostFailure(hostname) {
  try {
    hostFailureMap.set(hostname, Date.now());
  } catch (e) { /* ignore */ }
}

function isHostRecentlyFailed(hostname) {
  try {
    const t = hostFailureMap.get(hostname);
    if (!t) return false;
    return (Date.now() - t) < HOST_FAILURE_TTL * 1000;
  } catch (e) {
    return false;
  }
}