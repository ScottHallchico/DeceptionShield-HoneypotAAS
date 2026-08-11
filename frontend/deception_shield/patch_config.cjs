const fs = require('fs');
const path = '.vercel/output/config.json';
const cfg = JSON.parse(fs.readFileSync(path));

// Find the index of the filesystem handle or fallback route to insert before it
let insertIndex = cfg.routes.findIndex(r => r.handle === 'filesystem' || r.src === '/(.*)');
if (insertIndex === -1) insertIndex = 1;

cfg.routes.splice(insertIndex, 0, {
  src: '/api/(.*)',
  dest: 'http://54.197.208.25:8000/api/$1'
});

fs.writeFileSync(path, JSON.stringify(cfg, null, 2));
console.log('Patched config.json with API proxy.');
