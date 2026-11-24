# Vendored assets

## qrcode.js

- Source: https://github.com/kazuhikoarase/qrcode-generator, `js/dist/qrcode.js`
- Commit: `83b7e8fe3fddd3b0368dbafd6ce56995bd25e3c8` (2025-08-07)
- License: MIT, see `LICENSE` in this directory
- Size: 56 KB raw, ~12 KB gzipped

Not a build dependency: it is a single classic script, copied verbatim, served
by `core.js` at `/vendor/qrcode.js` with a one-day cache. The create page loads
it only when the reader asks for a QR code, so it costs nothing on a page load
that never uses it.

To update: copy the new `dist/qrcode.js` over this file, refresh the commit
above, and re-check the API the create page uses (`qrcode(0, 'M')`, `addData`,
`make`, `getModuleCount`, `isDark`).
