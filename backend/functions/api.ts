import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, PutCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { hasPermission, extractUserFromEvent, PERMISSIONS, Role } from './rbac';
import { randomUUID } from 'crypto';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE!;

interface APIResponse {
  statusCode: number;
  headers: Record<string, string>;
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

async function createAuditLog(action: string, userId: string, details: any): Promise<void> {
  try {
    await docClient.send(new PutCommand({
      TableName: TABLE_NAME,
      Item: {
        pk: 'AUDIT',
        sk: `${Date.now()}_${randomUUID()}`,
        action,
        userId,
        details,
        timestamp: new Date().toISOString()
      }
    }));
  } catch (error) {
    console.error('Failed to create audit log:', error);
  }
}

function validateRole(role: string): role is Role {
  return ['admin', 'operator', 'viewer'].includes(role);
}

function chunkArray<T>(array: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}

export const handler = async (event: any): Promise<APIResponse> => {
  try {
    const { httpMethod, path, pathParameters, body } = event;
    const user = extractUserFromEvent(event);

    if (!user) {
      return createErrorResponse(403, 'Authentication required');
    }

    if (!validateRole(user.role)) {
      return createErrorResponse(403, 'Invalid role');
    }

    // GET /resources
    if (httpMethod === 'GET' && path === '/resources') {
      if (!hasPermission(user.role, PERMISSIONS.READ_RESOURCES)) {
        return createErrorResponse(403, 'Insufficient permissions');
      }

      try {
        const result = await docClient.send(new ScanCommand({
          TableName: TABLE_NAME,
          FilterExpression: 'pk <> :auditPk',
          ExpressionAttributeValues: {
            ':auditPk': 'AUDIT'
          }
        }));

        return createResponse(200, {
          resources: result.Items || [],
          count: result.Count || 0
        });
      } catch (error) {
        console.error('Error scanning resources:', error);
        return createErrorResponse(500, 'Failed to retrieve resources');
      }
    }

    // POST /api/{tableIndex}/bulk
    const bulkImportMatch = path.match(/^\/api\/(\d+)\/bulk$/);
    if (httpMethod === 'POST' && bulkImportMatch) {
      if (!hasPermission(user.role, PERMISSIONS.BULK_IMPORT)) {
        return createErrorResponse(403, 'Insufficient permissions for bulk import');
      }

      if (!body) {
        return createErrorResponse(400, 'Request body is required');
      }

      let requestData;
      try {
        requestData = JSON.parse(body);
      } catch {
        return createErrorResponse(400, 'Invalid JSON in request body');
      }

      if (!requestData.items || !Array.isArray(requestData.items)) {
        return createErrorResponse(400, 'Request body must contain an "items" array');
      }

      const tableIndex = bulkImportMatch[1];
      const items = requestData.items;
      let imported = 0;
      let failed = 0;
      const errors: string[] = [];

      try {
        const chunks = chunkArray(items, 25);
        const now = new Date().toISOString();

        for (const chunk of chunks) {
          const writeRequests = chunk.map((item, index) => {
            const enrichedItem = {
              ...item,
              id: item.id || randomUUID(),
              pk: item.pk || `RESOURCE_${tableIndex}`,
              sk: item.sk || `${Date.now()}_${index}`,
              createdAt: now,
              updatedAt: now
            };

            return {
              PutRequest: {
                Item: enrichedItem
              }
            };
          });

          try {
            await docClient.send(new BatchWriteCommand({
              RequestItems: {
                [TABLE_NAME]: writeRequests
              }
            }));
            imported += chunk.length;
          } catch (error) {
            failed += chunk.length;
            errors.push(`Batch write failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
          }
        }

        await createAuditLog('BULK_IMPORT', user.id, {
          tableIndex,
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
        console.error('Bulk import error:', error);
        return createErrorResponse(500, 'Bulk import operation failed');
      }
    }

    return createErrorResponse(404, 'Endpoint not found');
  } catch (error) {
    console.error('Unexpected error:', error);
    return createErrorResponse(500, 'Internal server error');
  }
};