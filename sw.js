const CACHE = "kw66msg-v4";
const SHELL = ["./", "./index.html", "./app.js", "./manifest.json"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)));
  self.skipWaiting();
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener("fetch", e => {
  // Никогда не кэшируем Supabase-запросы (шифротекст/pairing-трафик) — только статический app shell.
  if (e.request.url.includes("supabase.co") || e.request.url.includes("jsdelivr.net")) return;
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});
