/**
 * Custom error classes for @dooz/sdk
 */

import type { ApiError } from './types';

/**
 * Base error class for Dooz SDK
 */
export class DoozError extends Error {
    public readonly code: string;
    public readonly details?: Record<string, unknown>;

    constructor(code: string, message: string, details?: Record<string, unknown>) {
        super(message);
        this.name = 'DoozError';
        this.code = code;
        this.details = details;
    }

    static fromApiError(error: ApiError): DoozError {
        return new DoozError(error.code, error.message, error.details);
    }
}

/**
 * Authentication error
 */
export class DoozAuthError extends DoozError {
    constructor(code: string, message: string, details?: Record<string, unknown>) {
        super(code, message, details);
        this.name = 'DoozAuthError';
    }
}

/**
 * Tenant context error
 */
export class DoozTenantError extends DoozError {
    constructor(code: string, message: string, details?: Record<string, unknown>) {
        super(code, message, details);
        this.name = 'DoozTenantError';
    }
}

/**
 * License error
 */
export class DoozLicenseError extends DoozError {
    constructor(code: string, message: string, details?: Record<string, unknown>) {
        super(code, message, details);
        this.name = 'DoozLicenseError';
    }
}

/**
 * Permission error
 */
export class DoozPermissionError extends DoozError {
    constructor(code: string, message: string, details?: Record<string, unknown>) {
        super(code, message, details);
        this.name = 'DoozPermissionError';
    }
}
