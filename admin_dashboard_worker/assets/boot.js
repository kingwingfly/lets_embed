import init from '/admin/pkg/admin_web.js';

init('/admin/pkg/admin_web_bg.wasm').catch((err) => {
  const root = document.getElementById('admin-root');
  if (root) {
    root.textContent = 'Failed to load admin dashboard bundle: ' + String(err);
  }
});
