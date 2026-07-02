// Minimal service worker — required by browser's for "Add to Home Screen" /
// install prompts to appear. Caches static assets only (HTML/CSS/JS/icons),
// never API responses, so attendance data is always fetched live and never
// served stale from cache.

const CACHE_NAME = "s-attendance-static-v1";
const STATIC_ASSETS = [
  "/",
  "/index.html",
  "/style.css",
  "/app.js",
  "/manifest.json",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // Never cache API calls (Render backend) or non-GET requests —
  // attendance, login, and all data must always be live.
  if (event.request.method !== "GET" || url.origin !== self.location.origin) {
    return;
  }

  // Network-first for the app shell so updates are picked up quickly,
  // falling back to cache only if offline.
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});