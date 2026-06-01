export type Role = 'admin' | 'operator' | 'viewer';

export interface User {
  id: string;
  role: Role;
  permissions: string[];
}

export const PERMISSIONS = {
  READ_RESOURCES: 'read:resources',
  WRITE_RESOURCES: 'write:resources',
  DELETE_RESOURCES: 'delete:resources',
  BULK_IMPORT: 'bulk:import'
} as const;

export const ROLE_PERMISSIONS: Record<Role, string[]> = {
  admin: [
    PERMISSIONS.READ_RESOURCES,
    PERMISSIONS.WRITE_RESOURCES,
    PERMISSIONS.DELETE_RESOURCES,
    PERMISSIONS.BULK_IMPORT
  ],
  operator: [
    PERMISSIONS.READ_RESOURCES,
    PERMISSIONS.WRITE_RESOURCES,
    PERMISSIONS.BULK_IMPORT
  ],
  viewer: [
    PERMISSIONS.READ_RESOURCES
  ]
};

export function hasPermission(role: Role, permission: string): boolean {
  return ROLE_PERMISSIONS[role].includes(permission);
}

export function extractUserFromEvent(event: any): User | null {
  try {
    const authHeader = event.headers?.Authorization || event.headers?.authorization;
    if (!authHeader) return null;
    
    const token = authHeader.replace('Bearer ', '');
    const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    
    return {
      id: decoded.sub || decoded.userId,
      role: decoded.role || 'viewer',
      permissions: ROLE_PERMISSIONS[decoded.role || 'viewer']
    };
  } catch {
    return null;
  }
}