import { createBuilder } from '@sgnl-ai/secevent';
import { createPrivateKey } from 'crypto';
import { transmitSET } from '@sgnl-ai/set-transmitter';
import {resolveJSONPathTemplates} from '@sgnl-actions/utils';

// Event type constant
const TOKEN_CLAIMS_CHANGE_EVENT = 'https://schemas.openid.net/secevent/caep/event-type/token-claims-change';


/**
 * Parse subject JSON string
 */
function parseSubject(subjectStr) {
  try {
    return JSON.parse(subjectStr);
  } catch (error) {
    throw new Error(`Invalid subject JSON: ${error.message}`);
  }
}

/**
 * Parse claims JSON string
 */
function parseClaims(claimsStr) {
  try {
    const claims = JSON.parse(claimsStr);
    if (typeof claims !== 'object' || claims === null || Array.isArray(claims)) {
      throw new Error('Claims must be a JSON object');
    }
    return claims;
  } catch (error) {
    throw new Error(`Invalid claims JSON: ${error.message}`);
  }
}

/**
 * Parse reason JSON if it's i18n format, otherwise return as string
 */
function parseReason(reasonStr) {
  if (!reasonStr) return reasonStr;

  // Try to parse as JSON for i18n format
  try {
    const parsed = JSON.parse(reasonStr);
    // If it's an object, it's likely i18n format
    if (typeof parsed === 'object' && parsed !== null) {
      return parsed;
    }
  } catch {
    // Not JSON, treat as plain string
  }

  return reasonStr;
}

/**
 * Build destination URL
 */
function buildUrl(address, suffix) {
  if (!suffix) {
    return address;
  }
  const baseUrl = address.endsWith('/') ? address.slice(0, -1) : address;
  const cleanSuffix = suffix.startsWith('/') ? suffix.slice(1) : suffix;
  return `${baseUrl}/${cleanSuffix}`;
}

export default {
  /**
   * Transmit a CAEP Token Claims Change event
   */
  invoke: async (params, context) => {
    const jobContext = context.data || {};

    // Resolve JSONPath templates in params
    const { result: resolvedParams, errors } = resolveJSONPathTemplates(params, jobContext);
    if (errors.length > 0) {
     console.warn('Template resolution errors:', errors);
    }

    // Validate required parameters
    if (!resolvedParams.audience) {
      throw new Error('audience is required');
    }
    if (!resolvedParams.subject) {
      throw new Error('subject is required');
    }
    if (!resolvedParams.address) {
      throw new Error('address is required');
    }
    if (!resolvedParams.claims) {
      throw new Error('claims is required');
    }

    // Get secrets
    const ssfKey = context.secrets?.SSF_KEY;
    const ssfKeyId = context.secrets?.SSF_KEY_ID;
    const authToken = context.secrets?.AUTH_TOKEN;

    if (!ssfKey) {
      throw new Error('SSF_KEY secret is required');
    }
    if (!ssfKeyId) {
      throw new Error('SSF_KEY_ID secret is required');
    }

    // Parse and validate parameters early
    const subject = parseSubject(resolvedParams.subject);
    const claims = parseClaims(resolvedParams.claims);

    const issuer = resolvedParams.issuer || 'https://sgnl.ai/';
    const signingMethod = resolvedParams.signingMethod || 'RS256';

    // Build event payload
    const eventPayload = {
      event_timestamp: resolvedParams.eventTimestamp || Math.floor(Date.now() / 1000),
      claims: claims
    };

    // Add optional event claims
    if (resolvedParams.initiatingEntity) {
      eventPayload.initiating_entity = resolvedParams.initiatingEntity;
    }
    if (resolvedParams.reasonAdmin) {
      eventPayload.reason_admin = parseReason(resolvedParams.reasonAdmin);
    }
    if (resolvedParams.reasonUser) {
      eventPayload.reason_user = parseReason(resolvedParams.reasonUser);
    }

    // Create the SET
    const builder = createBuilder();

    builder
      .withIssuer(issuer)
      .withAudience(resolvedParams.audience)
      .withIat(Math.floor(Date.now() / 1000))
      .withClaim('sub_id', subject)  // CAEP 3.0 format
      .withEvent(TOKEN_CLAIMS_CHANGE_EVENT, eventPayload);

    // Sign the SET
    const privateKeyObject = createPrivateKey(ssfKey);
    const signingKey = {
      key: privateKeyObject,
      alg: signingMethod,
      kid: ssfKeyId
    };

    const { jwt } = await builder.sign(signingKey);

    // Build destination URL
    const url = buildUrl(resolvedParams.address, resolvedParams.addressSuffix);

    // Transmit the SET
    const headers = {
      'User-Agent': resolvedParams.userAgent || 'SGNL-Action-Framework/1.0'
    };

    if (authToken) {
      headers.Authorization = authToken.startsWith('Bearer ')
        ? authToken
        : `Bearer ${authToken}`;
    }

    return await transmitSET(jwt, url, { headers });
  },

  /**
   * Error handler for retryable failures
   */
  error: async (params, _context) => {
    const { error } = params;

    // Check if this is a retryable error
    if (error.message?.includes('429') ||
        error.message?.includes('502') ||
        error.message?.includes('503') ||
        error.message?.includes('504')) {
      return { status: 'retry_requested' };
    }

    // Non-retryable error
    throw error;
  },

  /**
   * Cleanup handler
   */
  halt: async (_params, _context) => {
    return { status: 'halted' };
  }
};