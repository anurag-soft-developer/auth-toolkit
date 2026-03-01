module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module',
  },
  extends: [
    'eslint:recommended',
  ],
  rules: {
    'no-unused-vars': 'off',
    'prefer-const': 'error',
    'no-console': 'off',
    'no-useless-catch': 'off',
  },
  ignorePatterns: ['dist/', 'node_modules/', '*.js'],
  env: {
    node: true,
    es6: true,
  },
};