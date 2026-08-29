/**
 * genebank worker.js - NCBI GenBank 专用代理 Worker
 *
 * 适配说明：
 *  - 目标站点改为 www.ncbi.nlm.nih.gov
 *  - 额外识别 ncbi.nlm.nih.gov 及其子域资源
 *  - 保留 #hash、?query 和相对路径
 *  - 针对 NCBI 的页面结构和资源路径做兼容处理
 *  - 保留原项目的登录页 + Cookie 登录模式
 */

const PROXY_PASSWORD = '你的密码';
const PROXY_HOST = '你的域名';
const DEFAULT_ORIGIN = 'www.ncbi.nlm.nih.gov';
const PROXY_PREFIX = '/__proxy__/';
const LOGIN_PATH = '/__genebank_login';
const SESSION_COOKIE = 'genebank_proxy_session';
const SESSION_TTL = 60 * 60 * 24 * 7;

const TTL_HTML = 60 * 15;
const TTL_ASSET_SHORT = 60 * 60 * 12;
const TTL_ASSET_LONG = 60 * 60 * 24 * 30;
const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST', 'OPTIONS']);
const hostFailureMap = new Map();
const HOST_FAILURE_TTL = 60 * 60;

addEventListener('fetch', event => {
  event.respondWith(mainHandler(event.request));
});

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
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f5f7fb;color:#222}
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

async function mainHandler(request) {
  try {
    const url = new URL(request.url);

    if (url.pathname === LOGIN_PATH) return await handleLogin(request, url);

    if (!(await authenticate(request))) {
      return loginPage('', url.pathname + url.search);
    }

    if (!ALLOWED_METHODS.has(request.method)) {
      return new Response('Method Not Allowed', { status: 405 });
    }

    if (url.pathname === '/__genebank_proxy_ping') return new Response('ok', { status: 200 });

    if (url.pathname.startsWith(PROXY_PREFIX)) {
      return await handleProxyUpstream(request, url);
    }

    return await handleSiteRequest(request, url);
  } catch (err) {
    return errorPage('Unexpected server error: ' + (err && err.message ? err.message : String(err)));
  }
}

async function handleProxyUpstream(request, url) {
  try {
    const parts = url.pathname.split('/').filter(Boolean);
    if (parts.length < 2 || parts[0] !== '__proxy__') {
      return new Response('Bad proxy path', { status: 400 });
    }

    const hostname = parts[1];
    if (!/^[a-z0-9.-]+$/i.test(hostname)) {
      return new Response('Invalid host in proxy path', { status: 400 });
    }

    const path = '/' + parts.slice(2).join('/');
    const target = `https://${hostname}${path}${url.search}`;

    if (isHostRecentlyFailed(hostname)) {
      return errorPage(`Upstream host ${hostname} recently returned errors; try again later.`);
    }

    const forwardedReq = new Request(target, {
      method: request.method,
      headers: prepareForwardHeaders(request.headers, hostname),
      body: request.method === 'GET' || request.method === 'HEAD' ? null : request.body,
      redirect: 'follow'
    });

    const cache = caches.default;
    const cacheKey = new Request(target, { method: 'GET', headers: forwardedReq.headers });
    const likelyAsset = isLikelyAsset(path);

    if (likelyAsset) {
      try {
        const cached = await cache.match(cacheKey);
        if (cached) return cached;
      } catch (e) { /* ignore */ }
    }

    const cfOptions = { cacheTtl: likelyAsset ? TTL_ASSET_LONG : TTL_ASSET_SHORT, cacheEverything: true };

    let fetched;
    try {
      fetched = await fetch(forwardedReq, { cf: cfOptions });
    } catch (err) {
      markHostFailure(hostname);
      try {
        fetched = await fetch(target);
      } catch (err2) {
        markHostFailure(hostname);
        return errorPage(`Failed to fetch upstream ${hostname}: ${err2.message}`);
      }
    }

    if (fetched.status >= 500) {
      markHostFailure(hostname);
    }

    const cleanedHeaders = stripProblematicHeaders(fetched.headers);
    const resp = new Response(fetched.body, {
      status: fetched.status,
      statusText: fetched.statusText,
      headers: cleanedHeaders
    });

    if (fetched.status === 200 && likelyAsset) {
      resp.headers.set('Cache-Control', `public, max-age=${TTL_ASSET_LONG}`);
      eventualCachePut(cache, cacheKey, resp.clone()).catch(()=>{});
    } else if (fetched.status === 200) {
      resp.headers.set('Cache-Control', `public, max-age=${TTL_ASSET_SHORT}`);
    }

    resp.headers.set('X-GenBank-Proxy', 'upstream');
    return resp;
  } catch (err) {
    return errorPage('Proxy upstream handler error: ' + (err.message || String(err)));
  }
}

async function handleSiteRequest(request, url) {
  const cache = caches.default;
  const accept = (request.headers.get('Accept') || '').toLowerCase();
  const acceptsHtml = accept.includes('text/html');
  const likelyAsset = isLikelyAsset(url.pathname);

  if (likelyAsset || !acceptsHtml) {
    return await fetchAndCacheOrigin(request, url, { asset: true });
  }

  const cacheKey = new Request(request.url, request);
  try {
    const cached = await cache.match(cacheKey);
    if (cached) return cached;
  } catch (e) { /* ignore */ }

  const originUrl = `https://${DEFAULT_ORIGIN}${url.pathname}${url.search}`;
  const forwarded = new Request(originUrl, {
    method: request.method,
    headers: prepareForwardHeaders(request.headers, DEFAULT_ORIGIN),
    body: request.method === 'GET' || request.method === 'HEAD' ? null : request.body,
    redirect: 'follow'
  });

  let fetched;
  try {
    fetched = await fetch(forwarded, { cf: { cacheTtl: TTL_HTML, cacheEverything: true } });
  } catch (err) {
    return errorPage('Failed to fetch origin HTML: ' + (err.message || String(err)));
  }

  const contentType = (fetched.headers.get('content-type') || '').toLowerCase();
  if (!contentType.includes('text/html')) {
    return new Response(fetched.body, {
      status: fetched.status,
      statusText: fetched.statusText,
      headers: stripProblematicHeaders(fetched.headers)
    });
  }

  const documentBase = fetched.url || originUrl;
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
    .on('iframe', new AttrRewriter('src', documentBase))
    .on('*', new StyleAttrRewriter(documentBase));

  const transformed = rewriter.transform(fetched);

  const finalResp = new Response(transformed.body, {
    status: fetched.status,
    statusText: fetched.statusText,
    headers: stripProblematicHeaders(fetched.headers)
  });

  if (finalResp.status === 200) {
    finalResp.headers.set('Cache-Control', `public, max-age=${TTL_HTML}`);
    try { await cache.put(cacheKey, finalResp.clone()); } catch (e) { /* ignore */ }
  }

  finalResp.headers.set('X-GenBank-Proxy', 'html-rewritten');
  return finalResp;
}

async function fetchAndCacheOrigin(request, url, opts = {}) {
  const cache = caches.default;
  const path = url.pathname + url.search;
  const target = `https://${DEFAULT_ORIGIN}${path}`;

  const forwarded = new Request(target, {
    method: request.method,
    headers: prepareForwardHeaders(request.headers, DEFAULT_ORIGIN),
    body: request.method === 'GET' || request.method === 'HEAD' ? null : request.body,
    redirect: 'follow'
  });

  const cacheKey = new Request(target, {
    method: request.method,
    headers: prepareForwardHeaders(request.headers, DEFAULT_ORIGIN)
  });

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
      eventualCachePut(cache, cacheKey, resp.clone()).catch(()=>{});
    }

    resp.headers.set('X-GenBank-Proxy', 'origin-fetch');
    return resp;

  } catch (err) {
    return errorPage('Fetch origin asset failed: ' + (err.message || String(err)));
  }
}

function isLikelyAsset(pathname) {
  return /\.(png|jpe?g|gif|webp|svg|ico|css|js|mjs|woff2?|ttf|otf|map|mp4|webm|ogg|mp3|wav|flac|m4a|ogv|ogm|pdf|zip|gz|tar|bz2|xz)(\?.*)?$/i.test(pathname);
}

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

      if (this.attrName === 'srcset' || this.attrName === 'data-srcset') {
        const parts = raw.split(',').map(p => p.trim()).filter(Boolean);
        const mapped = parts.map(part => {
          const m = part.match(/^([^\s]+)(\s+[^\s]+)?$/);
          if (!m) return part;
          const urlPart = m[1];
          const desc = m[2] || '';
          const newUrl = makeProxyUrl(urlPart, this.documentBase);
          return `${newUrl}${desc}`;
        });
        el.setAttribute(this.attrName, mapped.join(', '));
        return;
      }

      const newVal = makeProxyUrl(raw, this.documentBase);
      if (newVal && newVal !== raw) el.setAttribute(this.attrName, newVal);
    } catch (e) {
      // ignore per-element errors
    }
  }
}

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

function isAlreadyProxied(val) {
  try {
    if (!val) return false;
    if (typeof val !== 'string') return false;
    if (val.startsWith(PROXY_PREFIX)) return true;
    const u = new URL(val, `https://${DEFAULT_ORIGIN}`);
    if (u.hostname === PROXY_HOST) return true;
    if (u.pathname && u.pathname.startsWith(PROXY_PREFIX)) return true;
    return false;
  } catch (e) {
    return false;
  }
}

function isNcbiHost(hostname) {
  const host = hostname.toLowerCase();
  return host === DEFAULT_ORIGIN || host === 'ncbi.nlm.nih.gov' || host.endsWith('.ncbi.nlm.nih.gov');
}

function makeProxyUrl(orig, documentBase = `https://${DEFAULT_ORIGIN}/`) {
  try {
    if (/^\s*#/.test(orig)) return orig;

    const u = new URL(orig, documentBase);
    const host = u.hostname.toLowerCase();
    if (isNcbiHost(host)) {
      return `https://${PROXY_HOST}${PROXY_PREFIX}${host}${u.pathname}${u.search || ''}${u.hash || ''}`;
    }
    return orig;
  } catch (e) {
    return orig;
  }
}

function prepareForwardHeaders(originalHeaders, upstreamHost) {
  const headers = new Headers();
  for (const [k, v] of originalHeaders) {
    const key = k.toLowerCase();
    if (['x-forwarded-for','cf-connecting-ip','cf-ray','via','connection','keep-alive','transfer-encoding','upgrade'].includes(key)) continue;
    if (key === 'host') continue;
    if (key === 'accept-encoding') continue;
    headers.set(k, v);
  }
  headers.set('Host', upstreamHost);
  if (!headers.has('referer') && !headers.has('referrer')) {
    headers.set('Referer', `https://${upstreamHost}/`);
  }
  if (!headers.has('user-agent')) headers.set('User-Agent', 'Mozilla/5.0 (compatible; genebank-proxy/1.0)');
  return headers;
}

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

async function eventualCachePut(cache, key, value) {
  try {
    await cache.put(key, value);
  } catch (e) {
    // ignore cache put failure
  }
}

function errorPage(message) {
  const safeMsg = String(message).replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const html = `<!doctype html>
  <html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>GenBank 代理不可用</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f7fb}
    .box{background:#fff;padding:26px;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,0.08);max-width:720px;text-align:center}
    h1{margin:0 0 12px;color:#c0392b}p{color:#333;line-height:1.6}a{color:#0b74de}
  </style></head><body>
    <div class="box">
      <h1>GenBank 代理暂时不可用</h1>
      <p>${safeMsg}</p>
      <p>你可以稍后再试，或直接访问源站：<a href="https://www.ncbi.nlm.nih.gov" target="_blank">https://www.ncbi.nlm.nih.gov</a></p>
    </div>
  </body></html>`;
  return new Response(html, { status: 502, headers: { 'content-type': 'text/html; charset=utf-8' } });
}

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
