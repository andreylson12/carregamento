const CACHE_NAME = "fila-agrex-pwa-v15-3";

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
   * As APIs sempre usam a internet.
   * Nunca entram no cache.
   */
  if (url.pathname.startsWith("/api/")) {
    event.respondWith(
      fetch(request)
    );

    return;
  }

  /*
   * A navegação tenta buscar primeiro
   * a versão mais nova no servidor.
   *
   * Se estiver sem internet,
   * usa a última página salva.
   */
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy =
            response.clone();

          caches
            .open(CACHE_NAME)
            .then((cache) =>
              cache.put(
                "/",
                copy
              )
            );

          return response;
        })
        .catch(() =>
          caches.match("/")
        )
    );

    return;
  }

  /*
   * Arquivos locais:
   *
   * tenta primeiro buscar a versão nova.
   *
   * Se não conseguir,
   * usa o cache.
   *
   * Isso ajuda os celulares a receberem
   * index, manifest e ícones atualizados.
   */
  if (
    url.origin ===
    self.location.origin
  ) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy =
            response.clone();

          caches
            .open(CACHE_NAME)
            .then((cache) =>
              cache.put(
                request,
                copy
              )
            );

          return response;
        })
        .catch(() =>
          caches.match(request)
        )
    );
  }
});
