/**
 * ============================================================================
 * Safe Logger Utility
 * ============================================================================
 */

const DEFAULT_MASK_CHAR = '*';

interface MaskOptions {
    visiblePercent?: number;
    minVisible?: number;
    maskChar?: string;
}

/**
 * Normalize key names.
 *
 * Examples:
 *  AccessToken      -> accesstoken
 *  access_token     -> accesstoken
 *  ACCESS-TOKEN     -> accesstoken
 *  access.token     -> accesstoken
 *  Access Token     -> accesstoken
 */
function normalizeKey(key: string): string {
    return key
        .trim()
        .toLowerCase()
        .replace(/[\s._-]/g, '');
}

/**
 * Generic masking
 */
export function maskValue(
    value: string,
    options: MaskOptions = {},
): string {
    const {
        visiblePercent = 0.2,
        minVisible = 2,
        maskChar = DEFAULT_MASK_CHAR,
    } = options;

    if (!value) {
        return value;
    }

    const length = value.length;

    const visible = Math.max(
        minVisible,
        Math.floor(length * visiblePercent),
    );

    if (visible >= length) {
        return value;
    }

    return (
        maskChar.repeat(length - visible) +
        value.slice(length - visible)
    );
}

/**
 * Password
 */
function maskPassword(): string {
    return '********';
}

/**
 * Email
 *
 * john.doe@gmail.com
 * ->
 * j******e@gmail.com
 */
function maskEmail(email: string): string {
    const parts = email.split('@');

    if (parts.length !== 2) {
        return maskValue(email);
    }

    const [name, domain] = parts;

    if (name.length <= 2) {
        return `**@${domain}`;
    }

    return (
        name[0] +
        '*'.repeat(name.length - 2) +
        name[name.length - 1] +
        '@' +
        domain
    );
}

/**
 * Phone
 *
 * 0901234567
 * ->
 * ******4567
 */
function maskPhone(phone: string): string {
    const digits = phone.replace(/\D/g, '');

    if (digits.length <= 4) {
        return phone;
    }

    return (
        '*'.repeat(digits.length - 4) +
        digits.slice(-4)
    );
}

/**
 * Credit Card
 */
function maskCreditCard(card: string): string {
    return maskValue(card.replace(/\s/g, ''), {
        visiblePercent: 0.25,
        minVisible: 4,
    });
}

/**
 * JWT / API Key / Token
 */
function maskToken(token: string): string {
    return maskValue(token, {
        visiblePercent: 0.1,
        minVisible: 4,
    });
}

/**
 * ============================================================================
 * Exact field rules
 * ============================================================================
 */

const FIELD_MASKERS = new Map<
    string,
    (value: string) => string
>([
    ['password', maskPassword],
    ['passwd', maskPassword],
    ['pwd', maskPassword],

    ['email', maskEmail],
    ['phone', maskPhone],

    ['creditcard', maskCreditCard],
    ['cvv', () => '***'],

    ['jwt', maskToken],
    ['token', maskToken],
    ['accesstoken', maskToken],
    ['refreshtoken', maskToken],
    ['authorization', maskToken],
    ['apikey', maskToken],
    ['secret', maskToken],
    ['cookie', maskToken],
]);

/**
 * ============================================================================
 * Keyword detection
 * ============================================================================
 */

const SENSITIVE_KEYWORDS = [
    'password',
    'passwd',
    'pwd',

    'token',
    'jwt',
    'bearer',

    'secret',
    'apikey',

    'authorization',
    'cookie',

    'creditcard',
    'cardnumber',
    'cvv',

    'otp',

    'privatekey',

    'clientsecret',

    'accesstoken',
    'refreshtoken',
];

/**
 * Returns true if the field name is sensitive.
 *
 * Examples:
 *
 * accessToken
 * githubAccessToken
 * stripe_api_key
 * firebaseJWT
 * oauth_refresh_token
 */
function isSensitiveKey(key: string): boolean {
    const normalized = normalizeKey(key);

    return SENSITIVE_KEYWORDS.some(keyword =>
        normalized.includes(keyword),
    );
}

/**
 * ============================================================================
 * Main recursive sanitizer
 * ============================================================================
 */

function sanitize(value: unknown): unknown {
    if (value === null || value === undefined) {
        return value;
    }

    if (Array.isArray(value)) {
        return value.map(sanitize);
    }

    if (typeof value !== 'object') {
        return value;
    }

    const obj = value as Record<string, unknown>;

    return Object.fromEntries(
        Object.entries(obj).map(([key, value]) => {

            if (typeof value === 'string') {

                const normalized = normalizeKey(key);

                /**
                 * 1. Exact rule
                 */
                const masker = FIELD_MASKERS.get(normalized);

                if (masker) {
                    return [key, masker(value)];
                }

                /**
                 * 2. Keyword rule
                 */
                if (isSensitiveKey(normalized)) {
                    return [key, maskToken(value)];
                }

                /**
                 * 3. Keep original
                 */
                return [key, value];
            }

            if (
                value &&
                typeof value === 'object'
            ) {
                return [key, sanitize(value)];
            }

            return [key, value];
        }),
    );
}

/**
 * Public API
 */
export function safeLog<T>(value: T): T {
    return sanitize(value) as T;
}