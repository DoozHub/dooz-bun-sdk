/**
 * @dooz/sdk - TypeScript/Bun SDK for Dooz Core
 * 
 * This SDK provides a client for integrating external applications
 * with Dooz Core functionality including:
 * - Tenant context
 * - License checking
 * - Feature flags
 * - Permission management
 * - Audit logging
 */

// Main exports
export { DoozClient } from './client';
export { createDoozClient } from './client';

// Type exports
export type {
    DoozConfig,
    Tenant,
    TenantConfig,
    LicenseInfo,
    SeatInfo,
    Feature,
    PermissionResult,
    Role,
    AuditEntry,
    TokenInfo,
    ApiResponse,
    ApiError,
} from './types';

// Utility exports
export { DoozError, DoozAuthError, DoozTenantError, DoozLicenseError } from './errors';
