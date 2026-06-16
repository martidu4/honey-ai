import js from '@eslint/js';

export default [
    {
        ignores: ['node_modules/**', 'logs/**', 'honeyfs/**', 'eslint.config.mjs']
    },
    js.configs.recommended,
    {
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'commonjs',
            globals: {
                // Node.js globals
                require: 'readonly',
                module: 'readonly',
                exports: 'readonly',
                __dirname: 'readonly',
                __filename: 'readonly',
                process: 'readonly',
                console: 'readonly',
                Buffer: 'readonly',
                setTimeout: 'readonly',
                setInterval: 'readonly',
                clearTimeout: 'readonly',
                clearInterval: 'readonly',
                global: 'writable',
                fetch: 'readonly',
                URL: 'readonly',
                AbortController: 'readonly',
            }
        },
        rules: {
            // Errors that matter
            'no-unused-vars': ['warn', { argsIgnorePattern: '^_|^err$|^e$', varsIgnorePattern: '^_' }],
            'no-undef': 'error',
            'no-constant-condition': ['error', { checkLoops: false }],

            // Style consistency (light touch — Prettier handles formatting)
            'no-var': 'error',
            'prefer-const': 'warn',
            'eqeqeq': ['warn', 'smart'],
            'no-throw-literal': 'error',

            // Honeypot-specific: allow intentionally dangerous-looking code
            'no-eval': 'off',
            'no-implied-eval': 'off',
            // Security filters legitimately use control chars and escape sequences
            'no-control-regex': 'off',
            // Empty catch blocks are intentional (swallow errors gracefully in production)
            'no-empty': ['error', { allowEmptyCatch: true }],
            // Some regex in security patterns need complex escapes
            'no-useless-escape': 'warn',
        }
    },
    {
        // Test files: relax unused vars and empty blocks
        files: ['test-qa.js', 'test-stress.js'],
        rules: {
            'no-unused-vars': 'off',
            'no-empty': 'off'
        }
    }
];
