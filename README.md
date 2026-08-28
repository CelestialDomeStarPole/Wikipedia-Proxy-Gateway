# 中文维基百科 Cloudflare Worker 代理

这是一个使用 Cloudflare Worker 代理中文维基百科的单文件项目。Worker 会将中文维基页面、维基媒体资源和页面内链接转发到代理域名，并提供独立的密钥登录页面。  
复刻自[zyhgov/Wikipedia-Proxy-Gateway](https://github.com/zyhgov/Wikipedia-Proxy-Gateway)  
项目预览[预览网站](wiki.cdsp.us.ci) 密钥：password

## 功能

- 代理 `zh.wikipedia.org` 页面。
- 重写 Wikipedia、Wikimedia 链接，使资源继续通过代理访问。
- 支持图片、脚本、样式、视频、字体和 `srcset` 等资源。
- 使用 Cloudflare Edge Cache 缓存 HTML 和静态资源。
- 使用网页密钥登录

## 部署前准备

你需要准备：

- 一个 Cloudflare 账号。
- 一个已经接入 Cloudflare 的域名，例如 `wiki.example.com`。

## 修改配置

打开 [worker.js](worker.js)，修改文件开头的配置：

```js
const PROXY_PASSWORD = '替换为访问密钥';
const PROXY_HOST = 'wiki.example.com';
```

`PROXY_HOST` 必须填写最终访问 Worker 的完整域名，不能包含协议、路径或结尾斜杠。

建议使用长度较长、随机生成的访问密钥。不要把真实密钥提交到公开仓库。生产环境更推荐将密钥改为 Cloudflare Worker Secret，并相应调整代码读取方式。

## 使用 Cloudflare 控制台部署

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)。
2. 进入 **Workers & Pages**，点击 **Create application**。
3. 选择 **Create Worker**，输入 Worker 名称并创建。
4. 打开 Worker 的代码编辑器，将修改后的 `worker.js` 复制进去，并点击**Deploy**
5. 在 Worker 的 **Settings > Domains & Routes** 中添加自定义域名。
6. 确认 DNS 记录由 Cloudflare 代理，并等待配置生效。

如果使用 Workers Routes 而不是 Custom Domain，请添加类似下面的路由：

```text
wiki.example.com/*
```

并将该路由绑定到此 Worker。
