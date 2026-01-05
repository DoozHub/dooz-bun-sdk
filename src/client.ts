/**
 * DoozClient - Main SDK client for Dooz Core integration
 */

import type {
    DoozConfig,
    Tenant,
    TenantConfig,
    LicenseInfo,
    SeatInfo,
    Feature,
    PermissionResult,
    PermissionsResult,
    Role,
    AuditEntry,
    TokenInfo,
    ApiResponse,
    ApiError,
} from './types';

import {
    DoozError,
    DoozAuthError,
    DoozTenantError,
    DoozLicenseError,
} from './errors';

/**
 * Cache entry with expiration
 */
interface CacheEntry<T> {
    data: T;
    expiresAt: number;
}

/**
 * Main Dooz SDK Client
 * 
 * @example
 * ```typescript
 * import { DoozClient } from '@dooz/sdk';
 * 
 * const dooz = new DoozClient({
 *     apiEndpoint: 'https://api.dooz.app',
 *     serviceToken: process.env.DOOZ_SERVICE_TOKEN,
 * });
 * 
 * // Check license
 * if (await dooz.hasLicense('my-app')) {
 *     // User has access
 * }
 * ```
 */
export class DoozClient {
    private readonly config: Required<DoozConfig>;
    private readonly cache: Map<string, CacheEntry<unknown>> = new Map();
    private token: string | null = null;

    constructor(config: DoozConfig) {
        this.config = {
            apiEndpoint: config.apiEndpoint.replace(/\/$/, ''),
            serviceToken: config.serviceToken ?? '',
            userToken: config.userToken ?? '',
            tenantId: config.tenantId ?? '',
            debug: config.debug ?? false,
            timeout: config.timeout ?? 30000,
            cacheEnabled: config.cacheEnabled ?? true,
            cacheTtl: config.cacheTtl ?? 300,
        };

        this.token = config.serviceToken ?? config.userToken ?? null;
    }

    /**
     * Create a new client instance with a user token
     */
    withUserToken(userToken: string): DoozClient {
        return new DoozClient({
            ...this.config,
            serviceToken: undefined,
            userToken,
        });
    }

    /**
     * Create a new client instance scoped to a tenant
     */
    forTenant(tenantId: string): DoozClient {
        return new DoozClient({
            ...this.config,
            tenantId,
        });
    }

    // ============================================
    // Authentication
    // ============================================

    /**
     * Exchange app credentials for a service token
     */
    async authenticate(appId: string, appSecret: string, tenantId?: string): Promise<TokenInfo> {
        const response = await this.request<ApiResponse<TokenInfo>>(
            'POST',
            '/auth/token',
            {
                app_id: appId,
                app_secret: appSecret,
                tenant_id: tenantId,
            },
            false
        );

        if (!response.success) {
            throw new DoozAuthError('AUTH_FAILED', 'Failed to authenticate');
        }

        this.token = response.data.accessToken;
        return response.data;
    }

    /**
     * Validate the current token
     */
    async validateToken(): Promise<boolean> {
        try {
            const response = await this.request<ApiResponse<{ valid: boolean }>>(
                'POST',
                '/auth/validate'
            );
            return response.success && response.data.valid;
        } catch {
            return false;
        }
    }

    // ============================================
    // Tenant
    // ============================================

    /**
     * Get current tenant context
     */
    async getCurrentTenant(): Promise<Tenant> {
        const cached = this.getFromCache<Tenant>('tenant:current');
        if (cached) return cached;

        const response = await this.request<ApiResponse<Tenant>>('GET', '/tenant/current');

        if (!response.success) {
            throw new DoozTenantError('NO_TENANT_CONTEXT', 'No tenant context available');
        }

        this.setCache('tenant:current', response.data);
        return response.data;
    }

    /**
     * Get tenant configuration
     */
    async getTenantConfig(): Promise<TenantConfig> {
        const cached = this.getFromCache<TenantConfig>('tenant:config');
        if (cached) return cached;

        const response = await this.request<ApiResponse<TenantConfig>>('GET', '/tenant/config');

        if (!response.success) {
            throw new DoozTenantError('NO_TENANT_CONTEXT', 'No tenant context available');
        }

        this.setCache('tenant:config', response.data);
        return response.data;
    }

    // ============================================
    // License
    // ============================================

    /**
     * Check if tenant has a valid license for an app
     */
    async hasLicense(appName: string, userId?: string): Promise<boolean> {
        const info = await this.getLicenseInfo(appName, userId);
        return info.hasLicense && info.hasSeat;
    }

    /**
     * Get detailed license information
     */
    async getLicenseInfo(appName: string, userId?: string): Promise<LicenseInfo> {
        const cacheKey = `license:${appName}:${userId ?? 'default'}`;
        const cached = this.getFromCache<LicenseInfo>(cacheKey);
        if (cached) return cached;

        const params = new URLSearchParams();
        if (userId) params.set('user_id', userId);

        const url = `/license/check/${encodeURIComponent(appName)}${params.toString() ? '?' + params : ''}`;
        const response = await this.request<ApiResponse<{
            app_name: string;
            has_license: boolean;
            has_seat: boolean;
            license_status: string | null;
            expires_at: string | null;
            is_trial: boolean;
        }>>('GET', url);

        if (!response.success) {
            throw new DoozLicenseError('LICENSE_CHECK_FAILED', 'Failed to check license');
        }

        const result: LicenseInfo = {
            appName: response.data.app_name,
            hasLicense: response.data.has_license,
            hasSeat: response.data.has_seat,
            licenseStatus: response.data.license_status,
            expiresAt: response.data.expires_at,
            isTrial: response.data.is_trial,
        };

        this.setCache(cacheKey, result);
        return result;
    }

    /**
     * Get seat information for an app
     */
    async getSeats(appName: string): Promise<SeatInfo> {
        const cacheKey = `seats:${appName}`;
        const cached = this.getFromCache<SeatInfo>(cacheKey);
        if (cached) return cached;

        const response = await this.request<ApiResponse<{
            app_name: string;
            total_seats: number | null;
            used_seats: number;
            available_seats: number;
            is_unlimited: boolean;
        }>>('GET', `/license/seats/${encodeURIComponent(appName)}`);

        if (!response.success) {
            throw new DoozLicenseError('SEATS_CHECK_FAILED', 'Failed to get seat info');
        }

        const result: SeatInfo = {
            appName: response.data.app_name,
            totalSeats: response.data.total_seats,
            usedSeats: response.data.used_seats,
            availableSeats: response.data.available_seats,
            isUnlimited: response.data.is_unlimited,
        };

        this.setCache(cacheKey, result);
        return result;
    }

    // ============================================
    // Features
    // ============================================

    /**
     * Get all enabled features
     */
    async getFeatures(appName?: string): Promise<string[]> {
        const cacheKey = `features:${appName ?? 'all'}`;
        const cached = this.getFromCache<string[]>(cacheKey);
        if (cached) return cached;

        const params = new URLSearchParams();
        if (appName) params.set('app_name', appName);

        const url = `/license/features${params.toString() ? '?' + params : ''}`;
        const response = await this.request<ApiResponse<{ features: string[] }>>('GET', url);

        if (!response.success) {
            throw new DoozLicenseError('FEATURES_CHECK_FAILED', 'Failed to get features');
        }

        this.setCache(cacheKey, response.data.features);
        return response.data.features;
    }

    /**
     * Check if a specific feature is enabled
     */
    async hasFeature(feature: string, appName?: string): Promise<boolean> {
        const cacheKey = `feature:${feature}:${appName ?? 'all'}`;
        const cached = this.getFromCache<boolean>(cacheKey);
        if (cached !== undefined) return cached;

        const response = await this.request<ApiResponse<Feature>>('POST', '/license/has-feature', {
            feature,
            app_name: appName,
        });

        if (!response.success) {
            return false;
        }

        this.setCache(cacheKey, response.data.enabled);
        return response.data.enabled;
    }

    // ============================================
    // Permissions
    // ============================================

    /**
     * Check if user has a permission
     */
    async can(permission: string, userId?: string): Promise<boolean> {
        const response = await this.request<ApiResponse<PermissionResult>>('POST', '/permissions/check', {
            permission,
            user_id: userId,
        });

        return response.success && response.data.granted;
    }

    /**
     * Check multiple permissions at once
     */
    async canAll(permissions: string[], userId?: string): Promise<PermissionsResult> {
        const response = await this.request<ApiResponse<PermissionsResult>>('POST', '/permissions/check-many', {
            permissions,
            user_id: userId,
        });

        if (!response.success) {
            throw new DoozError('PERMISSION_CHECK_FAILED', 'Failed to check permissions');
        }

        return response.data;
    }

    /**
     * Get user's roles
     */
    async getRoles(userId?: string): Promise<string[]> {
        const params = new URLSearchParams();
        if (userId) params.set('user_id', userId);

        const url = `/permissions/roles${params.toString() ? '?' + params : ''}`;
        const response = await this.request<ApiResponse<Role>>('GET', url);

        if (!response.success) {
            throw new DoozError('ROLES_CHECK_FAILED', 'Failed to get roles');
        }

        return response.data.roles;
    }

    /**
     * Check if user has a role
     */
    async hasRole(role: string, userId?: string): Promise<boolean> {
        const response = await this.request<ApiResponse<{ has_role: boolean }>>('POST', '/permissions/has-role', {
            role,
            user_id: userId,
        });

        return response.success && response.data.has_role;
    }

    // ============================================
    // Audit
    // ============================================

    /**
     * Log an audit entry
     */
    async audit(
        action: string,
        metadata?: Record<string, unknown>,
        options?: {
            resourceType?: string;
            resourceId?: string;
            userId?: string;
            severity?: 'info' | 'warning' | 'error' | 'critical';
        }
    ): Promise<void> {
        await this.request<ApiResponse<AuditEntry>>('POST', '/audit/log', {
            action,
            metadata,
            resource_type: options?.resourceType,
            resource_id: options?.resourceId,
            user_id: options?.userId,
            severity: options?.severity ?? 'info',
        });
    }

    // ============================================
    // Trial
    // ============================================

    /**
     * Check if tenant is on trial
     */
    async isTrial(): Promise<boolean> {
        const tenant = await this.getCurrentTenant();
        return tenant.isTrial;
    }

    /**
     * Get remaining trial days
     */
    async trialDaysRemaining(): Promise<number> {
        const tenant = await this.getCurrentTenant();
        return tenant.trialDaysRemaining ?? 0;
    }

    // ============================================
    // Private Methods
    // ============================================

    /**
     * Make an HTTP request to the SDK API
     */
    private async request<T>(
        method: 'GET' | 'POST' | 'PUT' | 'DELETE',
        path: string,
        data?: unknown,
        authenticated: boolean = true
    ): Promise<T> {
        const url = `${this.config.apiEndpoint}/api/sdk/v1${path}`;
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        };

        if (authenticated && this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        if (this.config.tenantId) {
            headers['X-Tenant'] = this.config.tenantId;
        }

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

        try {
            if (this.config.debug) {
                console.log(`[DoozSDK] ${method} ${url}`, data);
            }

            const response = await fetch(url, {
                method,
                headers,
                body: data ? JSON.stringify(data) : undefined,
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            const json = await response.json();

            if (this.config.debug) {
                console.log(`[DoozSDK] Response:`, json);
            }

            if (!response.ok) {
                const error = json.error as ApiError | undefined;
                throw DoozError.fromApiError(error ?? {
                    code: 'HTTP_ERROR',
                    message: `HTTP ${response.status}: ${response.statusText}`,
                });
            }

            return json as T;
        } catch (error) {
            clearTimeout(timeoutId);

            if (error instanceof DoozError) {
                throw error;
            }

            if (error instanceof Error && error.name === 'AbortError') {
                throw new DoozError('TIMEOUT', 'Request timed out');
            }

            throw new DoozError(
                'NETWORK_ERROR',
                error instanceof Error ? error.message : 'Network request failed'
            );
        }
    }

    /**
     * Get value from cache
     */
    private getFromCache<T>(key: string): T | undefined {
        if (!this.config.cacheEnabled) return undefined;

        const entry = this.cache.get(key) as CacheEntry<T> | undefined;
        if (!entry) return undefined;

        if (Date.now() > entry.expiresAt) {
            this.cache.delete(key);
            return undefined;
        }

        return entry.data;
    }

    /**
     * Set value in cache
     */
    private setCache<T>(key: string, data: T): void {
        if (!this.config.cacheEnabled) return;

        this.cache.set(key, {
            data,
            expiresAt: Date.now() + this.config.cacheTtl * 1000,
        });
    }

    /**
     * Clear all cached data
     */
    clearCache(): void {
        this.cache.clear();
    }
}

/**
 * Create a DoozClient instance
 * 
 * @example
 * ```typescript
 * const dooz = createDoozClient({
 *     apiEndpoint: 'https://api.dooz.app',
 *     serviceToken: process.env.DOOZ_SERVICE_TOKEN,
 * });
 * ```
 */
export function createDoozClient(config: DoozConfig): DoozClient {
    return new DoozClient(config);
}
