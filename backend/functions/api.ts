import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, GetCommand, PutCommand, UpdateCommand, DeleteCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { User, hasPermission, extractUserFromEvent } from './rbac';
import { randomUUID } from 'crypto';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE!;

interface AuditLog {
  pk: string;
  sk: string;
  action: string;
  userId: string;
  timestamp: string;
  details: Record<string, any>;
}

async function createAuditLog(user: User, action: string, details: Record<string, any>): Promise<void> {
  const auditLog: AuditLog = {
    pk: 'AUDIT',
    sk: `${Date.now()}_${randomUUID()}`,
    action,
    userId: user.id,
    timestamp: new Date().toISOString(),
    details
  };
  
  await docClient.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: auditLog
  }));
}

function createResponse(statusCode: number, body: any): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    },
    body: JSON.stringify(body)
  };
}

function validateResourceItem(item: any): string[] {
  const errors: string[] = [];
  
  if (!item.name || typeof item.name !== 'string') {
    errors.push('name is required and must be a string');
  }
  
  if (item.status && !['active', 'inactive', 'pending'].includes(item.status)) {
    errors.push('status must be one of: active, inactive, pending');
  }
  
  return errors;
}

async function handleGetResources(event: APIGatewayProxyEvent, user: User): Promise<APIGatewayProxyResult> {
  if (!hasPermission(user, 'resources', 'read')) {
    return createResponse(403, { error: 'Insufficient permissions' });
  }
  
  try {
    const result = await docClient.send(new ScanCommand({
      TableName: TABLE_NAME,
      FilterExpression: 'begins_with(pk, :pk)',
      ExpressionAttributeValues: {
        ':pk': 'RESOURCE#'
      }
    }));
    
    return createResponse(200, {
      items: result.Items || [],
      count: result.Count || 0
    });
  } catch (error) {
    console.error('Error fetching resources:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
}

async function handleGetResource(event: APIGatewayProxyEvent, user: User): Promise<APIGatewayProxyResult> {
  if (!hasPermission(user, 'resources', 'read')) {
    return createResponse(403, { error: 'Insufficient permissions' });
  }
  
  const resourceId = event.pathParameters?.id;
  if (!resourceId) {
    return createResponse(400, { error: 'Resource ID is required' });
  }
  
  try {
    const result = await docClient.send(new GetCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: `RESOURCE#${resourceId}`,
        sk: `RESOURCE#${resourceId}`
      }
    }));
    
    if (!result.Item) {
      return createResponse(404, { error: 'Resource not found' });
    }
    
    return createResponse(200, result.Item);
  } catch (error) {
    console.error('Error fetching resource:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
}

async function handleCreateResource(event: APIGatewayProxyEvent, user: User): Promise<APIGatewayProxyResult> {
  if (!hasPermission(user, 'resources', 'create')) {
    return createResponse(403, { error: 'Insufficient permissions' });
  }
  
  let requestBody;
  try {
    requestBody = JSON.parse(event.body || '{}');
  } catch (error) {
    return createResponse(400, { error: 'Invalid JSON in request body' });
  }
  
  const validationErrors = validateResourceItem(requestBody);
  if (validationErrors.length > 0) {
    return createResponse(400, { error: 'Validation failed', details: validationErrors });
  }
  
  const resourceId = randomUUID();
  const now = new Date().toISOString();
  
  const resource = {
    pk: `RESOURCE#${resourceId}`,
    sk: `RESOURCE#${resourceId}`,
    id: resourceId,
    ...requestBody,
    createdAt: now,
    updatedAt: now,
    createdBy: user.id
  };
  
  try {
    await docClient.send(new PutCommand({
      TableName: TABLE_NAME,
      Item: resource
    }));
    
    await createAuditLog(user, 'CREATE_RESOURCE', { resourceId, resource });
    
    return createResponse(201, resource);
  } catch (error) {
    console.error('Error creating resource:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
}

async function handleUpdateResource(event: APIGatewayProxyEvent, user: User): Promise<APIGatewayProxyResult> {
  if (!hasPermission(user, 'resources', 'update')) {
    return createResponse(403, { error: 'Insufficient permissions' });
  }
  
  const resourceId = event.pathParameters?.id;
  if (!resourceId) {
    return createResponse(400, { error: 'Resource ID is required' });
  }
  
  let requestBody;
  try {
    requestBody = JSON.parse(event.body || '{}');
  } catch (error) {
    return createResponse(400, { error: 'Invalid JSON in request body' });
  }
  
  const validationErrors = validateResourceItem(requestBody);
  if (validationErrors.length > 0) {
    return createResponse(400, { error: 'Validation failed', details: validationErrors });
  }
  
  try {
    const existing = await docClient.send(new GetCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: `RESOURCE#${resourceId}`,
        sk: `RESOURCE#${resourceId}`
      }
    }));
    
    if (!existing.Item) {
      return createResponse(404, { error: 'Resource not found' });
    }
    
    const updatedResource = {
      ...existing.Item,
      ...requestBody,
      updatedAt: new Date().toISOString(),
      updatedBy: user.id
    };
    
    await docClient.send(new PutCommand({
      TableName: TABLE_NAME,
      Item: updatedResource
    }));
    
    await createAuditLog(user, 'UPDATE_RESOURCE', { resourceId, changes: requestBody });
    
    return createResponse(200, updatedResource);
  } catch (error) {
    console.error('Error updating resource:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
}

async function handleDeleteResource(event: APIGatewayProxyEvent, user: User): Promise<APIGatewayProxyResult> {
  if (!hasPermission(user, 'resources', 'delete')) {
    return createResponse(403, { error: 'Insufficient permissions' });
  }
  
  const resourceId = event.pathParameters?.id;
  if (!resourceId) {
    return createResponse(400, { error: 'Resource ID is required' });
  }
  
  try {
    const existing = await docClient.send(new GetCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: `RESOURCE#${resourceId}`,
        sk: `RESOURCE#${resourceId}`
      }
    }));
    
    if (!existing.Item) {
      return createResponse(404, { error: 'Resource not found' });
    }
    
    await docClient.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: `RESOURCE#${resourceId}`,
        sk: `RESOURCE#${resourceId}`
      }
    }));
    
    await createAuditLog(user, 'DELETE_RESOURCE', { resourceId });
    
    return createResponse(200, { message: 'Resource deleted successfully' });
  } catch (error) {
    console.error('Error deleting resource:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
}

async function handleBulkImport(event: APIGatewayProxyEvent, user: User): Promise<APIGatewayProxyResult> {
  if (!hasPermission(user, 'resources', 'bulk')) {
    return createResponse(403, { error: 'Insufficient permissions' });
  }
  
  let requestBody;
  try {
    requestBody = JSON.parse(event.body || '{}');
  } catch (error) {
    return createResponse(400, { error: 'Invalid JSON in request body' });
  }
  
  if (!requestBody.items || !Array.isArray(requestBody.items)) {
    return createResponse(400, { error: 'items array is required' });
  }
  
  const items = requestBody.items;
  const errors: string[] = [];
  let imported = 0;
  let failed = 0;
  
  const now = new Date().toISOString();
  const processedItems = items.map((item, index) => {
    const validationErrors = validateResourceItem(item);
    if (validationErrors.length > 0) {
      errors.push(`Item ${index}: ${validationErrors.join(', ')}`);
      failed++;
      return null;
    }
    
    const resourceId = randomUUID();
    return {
      PutRequest: {
        Item: {
          pk: `RESOURCE#${resourceId}`,
          sk: `RESOURCE#${resourceId}`,
          id: resourceId,
          ...item,
          createdAt: now,
          updatedAt: now,
          createdBy: user.id
        }
      }
    };
  }).filter(item => item !== null);
  
  // Process in batches of 25 (DynamoDB limit)
  const batchSize = 25;
  for (let i = 0; i < processedItems.length; i += batchSize) {
    const batch = processedItems.slice(i, i + batchSize);
    
    try {
      await docClient.send(new BatchWriteCommand({
        RequestItems: {
          [TABLE_NAME]: batch
        }
      }));
      imported += batch.length;
    } catch (error) {
      console.error('Batch write error:', error);
      failed += batch.length;
      errors.push(`Batch ${Math.floor(i / batchSize) + 1}: Database write failed`);
    }
  }
  
  await createAuditLog(user, 'BULK_IMPORT_RESOURCES', {
    totalItems: items.length,
    imported,
    failed,
    errors: errors.length
  });
  
  return createResponse(200, {
    imported,
    failed,
    errors
  });
}

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  if (event.httpMethod === 'OPTIONS') {
    return createResponse(200, {});
  }
  
  let user: User;
  try {
    user = extractUserFromEvent(event);
  } catch (error) {
    return createResponse(401, { error: 'Unauthorized' });
  }
  
  const path = event.path;
  const method = event.httpMethod;
  
  try {
    if (method === 'GET' && path === '/resources') {
      return await handleGetResources(event, user);
    }
    
    if (method === 'GET' && path.match(/^\/resources\/[^/]+$/)) {
      return await handleGetResource(event, user);
    }
    
    if (method === 'POST' && path === '/resources') {
      return await handleCreateResource(event, user);
    }
    
    if (method === 'PUT' && path.match(/^\/resources\/[^/]+$/)) {
      return await handleUpdateResource(event, user);
    }
    
    if (method === 'DELETE' && path.match(/^\/resources\/[^/]+$/)) {
      return await handleDeleteResource(event, user);
    }
    
    if (method === 'POST' && path === '/api/0/bulk') {
      return await handleBulkImport(event, user);
    }
    
    return createResponse(404, { error: 'Endpoint not found' });
  } catch (error) {
    console.error('Unhandled error:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
};