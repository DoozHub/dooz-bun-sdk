/**
 * Type definitions for @dooz/sdk
 */

/**
 * SDK Configuration
 */
export interface DoozConfig {
    /** Dooz Core API endpoint (e.g., https://api.dooz.app) */
    apiEndpoint: string;

    /** Service token for SDK authentication */
    serviceToken?: string;

    /** User OAuth token for user-context operations */
    userToken?: string;

    /** Tenant ID to scope requests to */
    tenantId?: string;

    /** Enable debug logging */
    debug?: boolean;

    /** Request timeout in milliseconds (default: 30000) */
    timeout?: number;

    /** Enable response caching */
    cacheEnabled?: boolean;

    /** Cache TTL in seconds (default: 300) */
    cacheTtl?: number;
}

/**
 * Tenant information
 */
export interface Tenant {
    id: string;
    name: string;
    slug: string;
    domain: string | null;
    status: 'active' | 'trial' | 'suspended' | 'inactive';
    trialEndsAt: string | null;
    isTrial: boolean;
    trialDaysRemaining: number | null;
    createdAt: string;
}

/**
 * Tenant configuration
 */
export interface TenantConfig {
    tenantId: string;
    config: {
        timezone: string;
        locale: string;
        dateFormat: string;
        currency: string;
        features: string[];
    };
}

/**
 * License information
 */
export interface LicenseInfo {
    appName: string;
    hasLicense: boolean;
    hasSeat: boolean;
    licenseStatus: string | null;
    expiresAt: string | null;
    isTrial: boolean;
}

/**
 * Seat information
 */
export interface SeatInfo {
    appName: string;
    totalSeats: number | null;
    usedSeats: number;
    availableSeats: number;
    isUnlimited: boolean;
}

/**
 * Feature information
 */
export interface Feature {
    feature: string;
    enabled: boolean;
    source?: 'tenant' | 'license';
    appName?: string;
}

/**
 * Permission check result
 */
export interface PermissionResult {
    permission: string;
    userId: string;
    granted: boolean;
}

/**
 * Multiple permissions check result
 */
export interface PermissionsResult {
    userId: string;
    permissions: Record<string, boolean>;
    hasAll: boolean;
    hasAny: boolean;
}

/**
 * Role information
 */
export interface Role {
    userId: string;
    roles: string[];
}

/**
 * Audit log entry
 */
export interface AuditEntry {
    logged: boolean;
    action: string;
    timestamp: string;
}

/**
 * Token information
 */
export interface TokenInfo {
    accessToken: string;
    tokenType: 'Bearer';
    expiresIn: number;
    expiresAt: string;
    tenantId: string | null;
    scopes: string[];
}

/**
 * Generic API response wrapper
 */
export interface ApiResponse<T> {
    success: boolean;
    data: T;
    meta?: {
        requestId?: string;
    };
}

/**
 * API error response
 */
export interface ApiError {
    code: string;
    message: string;
    details?: Record<string, unknown>;
}
