export type Role = 'admin' | 'operator' | 'viewer';

export interface User {
  id: string;
  role: Role;
  email?: string;
}

export interface Permission {
  resource: string;
  action: 'create' | 'read' | 'update' | 'delete' | 'bulk';
}

const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  admin: [
    { resource: 'resources', action: 'create' },
    { resource: 'resources', action: 'read' },
    { resource: 'resources', action: 'update' },
    { resource: 'resources', action: 'delete' },
    { resource: 'resources', action: 'bulk' }
  ],
  operator: [
    { resource: 'resources', action: 'create' },
    { resource: 'resources', action: 'read' },
    { resource: 'resources', action: 'update' },
    { resource: 'resources', action: 'bulk' }
  ],
  viewer: [
    { resource: 'resources', action: 'read' }
  ]
};

export function hasPermission(user: User, resource: string, action: string): boolean {
  const permissions = ROLE_PERMISSIONS[user.role] || [];
  return permissions.some(p => p.resource === resource && p.action === action);
}

export function extractUserFromEvent(event: any): User {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  if (!authHeader) {
    throw new Error('Missing authorization header');
  }
  
  try {
    const token = authHeader.replace('Bearer ', '');
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    return {
      id: payload.sub || payload.userId || 'unknown',
      role: payload.role || 'viewer',
      email: payload.email
    };
  } catch (error) {
    throw new Error('Invalid token format');
  }
}