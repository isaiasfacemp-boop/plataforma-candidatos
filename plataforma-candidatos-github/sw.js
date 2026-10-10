// Service worker mínimo — só existe para o navegador permitir "Instalar app".
// Não guarda nada em cache, então o sistema sempre busca a versão mais nova.
self.addEventListener('install', function(event){
  self.skipWaiting();
});
self.addEventListener('activate', function(event){
  event.waitUntil(self.clients.claim());
});
self.addEventListener('fetch', function(event){
  event.respondWith(fetch(event.request));
});
