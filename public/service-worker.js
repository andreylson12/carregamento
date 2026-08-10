"use strict";

/*
 * FILA AGREX - PWA V15.2
 *
 * Cache novo para obrigar os aparelhos
 * a abandonarem o cache da V15 anterior.
 */
const CACHE_NAME =
  "fila-agrex-pwa-v15-2";

const APP_SHELL = [
  "/",
  "/manifest.json",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "/icons/apple-touch-icon.png"
];

/*
 * =========================================================
 * INSTALAÇÃO
 * =========================================================
 *
 * Cria o novo cache V15.2.
 *
 * Usamos cache: "reload" para tentar buscar
 * os arquivos atuais do servidor e não uma
 * cópia antiga guardada pelo navegador.
 */
self.addEventListener(
  "install",
  (event) => {

    event.waitUntil(
      caches
        .open(
          CACHE_NAME
        )
        .then(
          async (cache) => {

            for (
              const url of APP_SHELL
            ) {

              try {

                const response =
                  await fetch(
                    new Request(
                      url,
                      {
                        cache:
                          "reload"
                      }
                    )
                  );

                if (
                  response &&
                  response.ok
                ) {

                  await cache.put(
                    url,
                    response.clone()
                  );
                }

              } catch (
                error
              ) {

                console.warn(
                  "Não foi possível pré-carregar:",
                  url,
                  error
                );
              }
            }
          }
        )
        .then(
          () =>
            self.skipWaiting()
        )
    );
  }
);

/*
 * =========================================================
 * ATIVAÇÃO
 * =========================================================
 *
 * Apaga automaticamente caches antigos:
 *
 * fila-agrex-pwa-v15
 * ou qualquer outra versão anterior.
 */
self.addEventListener(
  "activate",
  (event) => {

    event.waitUntil(
      caches
        .keys()
        .then(
          (names) =>
            Promise.all(
              names
                .filter(
                  (name) =>
                    name !==
                    CACHE_NAME
                )
                .map(
                  (name) =>
                    caches.delete(
                      name
                    )
                )
            )
        )
        .then(
          () =>
            self.clients.claim()
        )
    );
  }
);

/*
 * =========================================================
 * REQUISIÇÕES
 * =========================================================
 */
self.addEventListener(
  "fetch",
  (event) => {

    const request =
      event.request;

    /*
     * Só trabalhamos com GET.
     *
     * POST / PATCH / DELETE etc.
     * seguem normalmente para o servidor.
     */
    if (
      request.method !==
      "GET"
    ) {
      return;
    }

    const url =
      new URL(
        request.url
      );

    /*
     * =====================================================
     * APIs
     * =====================================================
     *
     * Nunca entram no cache.
     *
     * Isso é importante para:
     *
     * - posição da fila;
     * - placas à frente;
     * - localização;
     * - painel;
     * - status;
     * - configurações.
     */
    if (
      url.pathname.startsWith(
        "/api/"
      )
    ) {

      event.respondWith(
        fetch(
          request
        )
      );

      return;
    }

    /*
     * =====================================================
     * NAVEGAÇÃO / INDEX.HTML
     * =====================================================
     *
     * Sempre tenta buscar a versão MAIS NOVA
     * no Railway.
     *
     * Se conseguir:
     * atualiza a cópia offline.
     *
     * Se ficar sem internet:
     * usa a última versão salva.
     */
    if (
      request.mode ===
      "navigate"
    ) {

      event.respondWith(
        fetch(
          request,
          {
            cache:
              "no-store"
          }
        )
          .then(
            async (
              response
            ) => {

              if (
                response &&
                response.ok
              ) {

                const copy =
                  response.clone();

                const cache =
                  await caches.open(
                    CACHE_NAME
                  );

                await cache.put(
                  "/",
                  copy
                );
              }

              return response;
            }
          )
          .catch(
            async () => {

              const cached =
                await caches.match(
                  "/"
                );

              if (
                cached
              ) {
                return cached;
              }

              return new Response(
                "Sem conexão com a internet.",
                {
                  status:
                    503,

                  headers: {
                    "Content-Type":
                      "text/plain; charset=utf-8"
                  }
                }
              );
            }
          )
      );

      return;
    }

    /*
     * =====================================================
     * ARQUIVOS LOCAIS
     * =====================================================
     *
     * Manifest e ícones:
     *
     * primeiro tenta usar cache;
     * se não existir, baixa e salva.
     */
    if (
      url.origin ===
      self.location.origin
    ) {

      event.respondWith(
        caches
          .match(
            request
          )
          .then(
            async (
              saved
            ) => {

              if (
                saved
              ) {
                return saved;
              }

              const response =
                await fetch(
                  request
                );

              if (
                response &&
                response.ok
              ) {

                const copy =
                  response.clone();

                const cache =
                  await caches.open(
                    CACHE_NAME
                  );

                await cache.put(
                  request,
                  copy
                );
              }

              return response;
            }
          )
      );
    }
  }
);
