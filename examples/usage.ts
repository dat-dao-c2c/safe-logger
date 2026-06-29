import { safeLog, registerFieldMasker } from '../src/index.js';

// --- Default behavior ---
const basicPayload = {
    username: 'john_doe',
    password: 'supersecretpassword'
};

console.log('--- Basic Masking ---');
console.log(safeLog(basicPayload));
// Output: { username: 'john_doe', password: '********' }


// --- Registering a new field with default masker (maskToken) ---
registerFieldMasker('internalCode');

const customFieldPayload = {
    internalCode: 'ABC-123456789'
};

console.log('\n--- Custom Field (Default Masker) ---');
console.log(safeLog(customFieldPayload));
// Output: { internalCode: '*********6789' }


// --- Registering a new field with a custom masker function ---
registerFieldMasker('customSecret', (value) => {
    return `[MASKED:${value.substring(0, 3)}...]`;
});

const customMaskerPayload = {
    customSecret: '123456789'
};

console.log('\n--- Custom Field (Custom Masker) ---');
console.log(safeLog(customMaskerPayload));
// Output: { customSecret: '[MASKED:123...]' }


// --- Deep Nesting ---
const deepPayload = {
    user: {
        profile: {
            password: 'deepPassword'
        }
    }
};

console.log('\n--- Deep Nesting ---');
console.log(safeLog(deepPayload));
// Output: { user: { profile: { password: '********' } } }


// --- AWS and SMTP edge cases ---
const cloudPayload = {
    AWS_SECRET_ACCESS_KEY: 'aws-secret-123',
    smtpPassword: 'smtp-password-123'
};

console.log('\n--- Cloud Edge Cases ---');
console.log(safeLog(cloudPayload));
// Output: { AWS_SECRET_ACCESS_KEY: '**********23', smtpPassword: '********' }
