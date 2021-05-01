<img src="https://driftbot.io/img/bot.svg" width="100px" />

# Driftbot - https://driftbot.io

A simple web app software supply chain monitoring toolkit.

## Goals

To provide a simple way for website/webapp owners to monitor their sites for unexpected changes in software supply chain profile (a.k.a. drift).

To use automation to detect things like:

- changes to sources where JavaScript files are loaded from (script hosts)
- changes to XHR/ajax request sources (xhr hosts)
- changes to WebSocket connection sources (websocket hosts)
- changes to WebWorker connection sources (webworker hosts)
- unseen JavaScript files that use heavy obfuscation - like hex, unicode, or escaping (obfuscation hosts)
- unseen JavaScript files that use suspicious function calls like `eval`, `atob`, and `btoa`

## How it works

Driftbot uses Puppeteer to drive a headless Chrome browser that interacts with your site like a real user would. It records and analyzes every JavaScript file and remote connection initiated by your site. Assuming your site isn't already compromised, monitoring for changes to this baseline can alert you that something (e.g. third-party package) has been exploited and needs further investigation.

## Setup

To run Driftbot on your site(s), you'll need to clone this repo and configure your site's URL. See the full setup guide at https://driftbot.io/howto.


## Development

Prerequisites:

- Node.js 14+
- Docker

If you'd like to test locally, make sure the headless browser container is running:

```
docker-compose up
```

Then, in another terminal, run the bot to test output:

```
node driftbot.js
```

Note that no GitHub Issues are created when running locally.

## Kudos

Driftbot is a simple project, but mainly because of the amazing work by the authors and of these projects:

- [Puppeteer](https://github.com/puppeteer/puppeteer)
- [Browserless](https://github.com/browserless/chrome)
- [Esprima](https://esprima.org/)
