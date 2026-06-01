import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, GetCommand, PutCommand, UpdateCommand, DeleteCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { getUserFromEvent, hasPermission, PERMISSIONS, User } from './rbac';
import { randomUUID } from 'crypto';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE!;

interface APIGatewayEvent {
  httpMethod: string;
  path: string;
  pathParameters?: { [key: string]: string } | null;
  queryStringParameters?: { [key: string]: string } | null;
  body?: string | null;
  requestContext: any;
}

interface APIResponse {
  statusCode: number;
  headers: { [key: string]: string };
  body: string;
}

function createResponse(statusCode: number, body: any): APIResponse {
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

function createErrorResponse(statusCode: number, message: string): APIResponse {
  return createResponse(statusCode, { error: message });
}

async function createAuditLog(user: User, action: string, details: any): Promise<void> {
  const auditItem = {
    pk: 'AUDIT',
    sk: `${Date.now()}_${randomUUID()}`,
    userId: user.id,
    userRole: user.role,
    action,
    details,
    timestamp: new Date().toISOString()
  };

  try {
    await docClient.send(new PutCommand({
      TableName: TABLE_NAME,
      Item: auditItem
    }));
  } catch (error) {
    console.error('Failed to create audit log:', error);
  }
}

async function getResources(user: User, queryParams: any): Promise<APIResponse> {
  if (!hasPermission(user, PERMISSIONS.RESOURCES_READ)) {
    return createErrorResponse(403, 'Insufficient permissions');
  }

  try {
    const command = new ScanCommand({
      TableName: TABLE_NAME,
      FilterExpression: 'attribute_exists(#pk) AND #pk <> :auditPk',
      ExpressionAttributeNames: {
        '#pk': 'pk'
      },
      ExpressionAttributeValues: {
        ':auditPk': 'AUDIT'
      }
    });

    const result = await docClient.send(command);
    return createResponse(200, {
      items: result.Items || [],
      count: result.Count || 0
    });
  } catch (error) {
    console.error('Error getting resources:', error);
    return createErrorResponse(500, 'Internal server error');
  }
}

async function bulkImportResources(user: User, body: string): Promise<APIResponse> {
  if (!hasPermission(user, PERMISSIONS.BULK_IMPORT)) {
    return createErrorResponse(403, 'Insufficient permissions');
  }

  try {
    const { items } = JSON.parse(body || '{}');
    
    if (!Array.isArray(items)) {
      return createErrorResponse(400, 'Items must be an array');
    }

    const now = new Date().toISOString();
    const processedItems = items.map(item => ({
      ...item,
      id: item.id || randomUUID(),
      pk: item.pk || `RESOURCE#${item.id || randomUUID()}`,
      sk: item.sk || `RESOURCE#${item.id || randomUUID()}`,
      createdAt: now,
      updatedAt: now
    }));

    let imported = 0;
    let failed = 0;
    const errors: string[] = [];

    // Process in batches of 25 (DynamoDB BatchWrite limit)
    for (let i = 0; i < processedItems.length; i += 25) {
      const batch = processedItems.slice(i, i + 25);
      
      try {
        const writeRequests = batch.map(item => ({
          PutRequest: {
            Item: item
          }
        }));

        await docClient.send(new BatchWriteCommand({
          RequestItems: {
            [TABLE_NAME]: writeRequests
          }
        }));

        imported += batch.length;
      } catch (error) {
        failed += batch.length;
        errors.push(`Batch ${Math.floor(i / 25) + 1}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }

    // Create audit log
    await createAuditLog(user, 'BULK_IMPORT', {
      totalItems: items.length,
      imported,
      failed
    });

    return createResponse(200, {
      imported,
      failed,
      errors
    });
  } catch (error) {
    console.error('Error in bulk import:', error);
    return createErrorResponse(500, 'Internal server error');
  }
}

export const handler = async (event: APIGatewayEvent): Promise<APIResponse> => {
  console.log('Event:', JSON.stringify(event, null, 2));

  if (event.httpMethod === 'OPTIONS') {
    return createResponse(200, {});
  }

  try {
    const user = getUserFromEvent(event);
    const path = event.path;
    const method = event.httpMethod;

    // Route handling
    if (method === 'GET' && path === '/resources') {
      return await getResources(user, event.queryStringParameters);
    }

    if (method === 'POST' && path.match(/^\/api\/\d+\/bulk$/)) {
      return await bulkImportResources(user, event.body || '');
    }

    return createErrorResponse(404, 'Endpoint not found');
  } catch (error) {
    console.error('Unhandled error:', error);
    return createErrorResponse(500, 'Internal server error');
  }
};