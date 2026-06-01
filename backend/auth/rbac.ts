export type Role = 'admin' | 'operator' | 'viewer';

export interface User {
  id: string;
  role: Role;
  permissions: string[];
}

export const PERMISSIONS = {
  RESOURCES_READ: 'resources:read',
  RESOURCES_WRITE: 'resources:write',
  RESOURCES_DELETE: 'resources:delete',
  BULK_IMPORT: 'bulk:import'
} as const;

export const ROLE_PERMISSIONS: Record<Role, string[]> = {
  admin: [
    PERMISSIONS.RESOURCES_READ,
    PERMISSIONS.RESOURCES_WRITE,
    PERMISSIONS.RESOURCES_DELETE,
    PERMISSIONS.BULK_IMPORT
  ],
  operator: [
    PERMISSIONS.RESOURCES_READ,
    PERMISSIONS.RESOURCES_WRITE,
    PERMISSIONS.BULK_IMPORT
  ],
  viewer: [
    PERMISSIONS.RESOURCES_READ
  ]
};

export function hasPermission(user: User, permission: string): boolean {
  return user.permissions.includes(permission) || ROLE_PERMISSIONS[user.role].includes(permission);
}

export function getUserFromEvent(event: any): User {
  const role = event.requestContext?.authorizer?.role || 'viewer';
  const userId = event.requestContext?.authorizer?.userId || 'anonymous';
  
  return {
    id: userId,
    role: role as Role,
    permissions: ROLE_PERMISSIONS[role as Role] || ROLE_PERMISSIONS.viewer
  };
}