import { defineConfig } from 'tsdown';

export default defineConfig({
  format: ['module'],
  platform: 'browser',
  minify: true,
  sourcemap: false,
  deps: {
    onlyBundle: false,
    alwaysBundle: [
      '@noble/curves/ed25519.js',
      '@noble/hashes/sha2.js',
      '@noble/hashes/utils.js',
      'quicvarint',
      'valibot',
    ],
  },
  dts: {
    generator: 'tsgo',
  },
  exports: true,
});
