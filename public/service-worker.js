const CACHE_NAME = "fila-agrex-pwa-v15";

const APP_SHELL = [
  "/",
  "/manifest.json",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "/icons/apple-touch-icon.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) =>
        Promise.all(
          names
            .filter((name) => name !== CACHE_NAME)
            .map((name) => caches.delete(name))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;

  if (request.method !== "GET") {
    return;
  }

  const url = new URL(request.url);

  /*
   * As APIs sempre usam a internet e nunca entram no cache.
   */
  if (url.pathname.startsWith("/api/")) {
    event.respondWith(fetch(request));
    return;
  }

  /*
   * A navegação tenta buscar a versão mais recente.
   * Sem internet, usa a última página salva.
   */
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy = response.clone();

          caches
            .open(CACHE_NAME)
            .then((cache) => cache.put("/", copy));

          return response;
        })
        .catch(() => caches.match("/"))
    );

    return;
  }

  /*
   * Ícones e arquivos locais usam o cache primeiro.
   */
  if (url.origin === self.location.origin) {
    event.respondWith(
      caches.match(request).then((saved) => {
        if (saved) {
          return saved;
        }

        return fetch(request).then((response) => {
          const copy = response.clone();

          caches
            .open(CACHE_NAME)
            .then((cache) => cache.put(request, copy));

          return response;
        });
      })
    );
  }
});
