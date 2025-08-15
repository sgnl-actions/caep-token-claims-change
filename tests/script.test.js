import { jest } from '@jest/globals';

// Mock the dependencies before importing the script
jest.unstable_mockModule('@sgnl-ai/secevent', () => ({
  createBuilder: jest.fn()
}));

jest.unstable_mockModule('@sgnl-ai/set-transmitter', () => ({
  transmitSET: jest.fn()
}));

jest.unstable_mockModule('crypto', () => ({
  createPrivateKey: jest.fn()
}));

// Import the modules after mocking
const { createBuilder } = await import('@sgnl-ai/secevent');
const { transmitSET } = await import('@sgnl-ai/set-transmitter');
const { createPrivateKey } = await import('crypto');
const script = await import('../src/script.mjs');

describe('CAEP Token Claims Change', () => {
  const validParams = {
    audience: 'https://receiver.example.com/',
    subject: '{"format":"account","uri":"acct:test@example.com"}',
    address: 'https://caep.receiver.com/events',
    claims: '{"role": "admin", "department": "finance"}'
  };

  const mockContext = {
    secrets: {
      SSF_KEY: `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCVP1FMSuoWHsTt
qnJ4BcVCADc3lFpnZjLsRiRs9WvqqdbYYrf0zqOrHoqbLMMGg601pnf20Y6e7xim
8KK7l2L7kVvfkIGPnDqwQWlkjEx5pBLQRz1WQdnz2hr6IpfZO4Z8zyjnySv/K5LU
nlJrzGdyHWmDKQAU9w4E2+zFmtcuwTM8mWJQoy3CBuwQ8/r+OsycRuxw0GvEA+yp
jm4PScbMFL+g8f2yPm1ACucrc/ogCSTv+yjbXJcdy95pgpOu/IrcbbyPJLE8+9Nt
eEr2gmNU8CzOHfflUJfAE7FHrCMJA593mKAlaULE2b53zAEVxuCSaKGiOJQ2ELhl
jRh+MeijAgMBAAECggEADDkw195E2MXxXAO7N1BFrRembhNk6hYJMqe2AQSCr6f0
VCmVpmOsLO4l7PqYCHcNXxkAt0LHewXbD4Ui1tlZvn/TtfY4XkIt3lSlJJqHAulo
rw0+nUtsZdfloLnnlN+Wrq8qyv0DcPUpI+fJmVGW4VY+V4Mqogzv5X77n92EJSyG
lMtLJCkB3AAP9ul5S4KbPs/GgMrLGKlMbfD8mTeZW0h5Bvgm34l/TLWLbnPQHtmF
HeMzYuwZjljpKNHfWc2L22soYvpcFS9CKzEozXa8DGkvEM9ZI8o1tHvFBOiFzUDn
Ydwl6dCm6m7PjnQ9GvR09UzPxTBLXwuKES/m28f75QKBgQDJhqOxW94it6pNtBKc
rd3+U1DqmBY4/pJ2R5y6I5vR9fMnG7s+9tXMrP7kV5bDXLJHVX5KKTB9ydO8PyA1
19fE3ftlIfDeZ1B+zTvwDsMyplEfOIqXMlKPViS1VvVU46HkHlwLB+nGyDSLtZPR
XQlzkmhFB6wGWaTBftYB+3qb1wKBgQC9lw9ISvhovGKVBBOCXycKvdvtW80phUyX
HQeXuTWYjaTP8a+0qNZ/zGgsgz+zEiXQQODreORR309p+3/DFl4YMm7SR/D6Fcc3
CKvFBQFv6wPnc+5tyOQoq32jXPp/XY5X8NUAPR3FbqwE40gQ2qXSOB/61H6l+m0C
JXVvMJHgFQKBgHKqo3WFWk3Sx5pS/cwcuhW9/mqdgveHEnsuoCThogXDtkjoZJCd
DmXZgWcX13btxZsFMEiuSyMntcyE9qTsXZ9s12BiAZXqn0inKpWbMMIfFEV5fJIv
Vf6s+1IbWpiktTcBd0nnhMNQo2VjOeqEz53tDltI1D8AvthCfS6/krIdAoGAQ4FQ
8LW5A1noZBTCeY410Y5Oi5I/V8RdxASTGoPYwIvWni/5FwNy9Kgsg4TsHm+cxS0E
qPMvoLM5jIv/LtB9CnKSoQ76j6FHgKH2vz0MCPSOPFA8Gh0ImC6PmqZVjxoZv9hB
j0cznYPNfiQLGe0wU8ymHmKhAapMPBJoYQHTPw0CgYAPyVbhsQf1M0Qu0ROxhbzY
qYeWeRz1GNGMqCHC1r1NFHuv0qvX2g7kVh2E3+OGu6Jr1TgzTXZMyFVRiPMokPQL
uMTJPqjqASAE4C6akEErJM2yY+3pVy+OHxd5ewZskchqY3YOI26uL9tEW3rzLp18
lUIPAweNrL/7ssEesKGGEw==
-----END PRIVATE KEY-----`,
      SSF_KEY_ID: 'test-key-id',
      AUTH_TOKEN: 'test-bearer-token'
    }
  };

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Setup default mocks
    const mockBuilder = {
      withIssuer: jest.fn().mockReturnThis(),
      withAudience: jest.fn().mockReturnThis(),
      withIat: jest.fn().mockReturnThis(),
      withClaim: jest.fn().mockReturnThis(),
      withEvent: jest.fn().mockReturnThis(),
      sign: jest.fn().mockResolvedValue({ jwt: 'mock.jwt.token' })
    };
    
    createBuilder.mockReturnValue(mockBuilder);
    createPrivateKey.mockReturnValue({ type: 'private' });
    
    transmitSET.mockResolvedValue({
      status: 'success',
      statusCode: 200,
      body: '"success"',
      retryable: false
    });
  });

  describe('invoke handler', () => {
    test('should successfully transmit SET with minimal required params', async () => {
      const result = await script.default.invoke(validParams, mockContext);

      expect(result.status).toBe('success');
      expect(result.statusCode).toBe(200);
      expect(result.body).toBe('"success"');
      expect(result.retryable).toBe(false);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://caep.receiver.com/events',
        {
          headers: {
            'Authorization': 'Bearer test-bearer-token',
            'User-Agent': 'SGNL-Action-Framework/1.0'
          }
        }
      );
    });

    test('should include all optional parameters in event payload', async () => {
      const fullParams = {
        ...validParams,
        initiatingEntity: 'policy',
        reasonAdmin: '{"en": "Token claims updated", "es": "Claims de token actualizados"}',
        reasonUser: '{"en": "Your permissions have changed", "es": "Tus permisos han cambiado"}',
        eventTimestamp: 1609459200,
        addressSuffix: '/caep',
        userAgent: 'Custom-Agent/1.0'
      };

      const result = await script.default.invoke(fullParams, mockContext);

      expect(result.status).toBe('success');
      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://caep.receiver.com/events/caep',
        {
          headers: {
            'Authorization': 'Bearer test-bearer-token',
            'User-Agent': 'Custom-Agent/1.0'
          }
        }
      );
    });

    test('should validate required parameters', async () => {
      const testCases = [
        { params: { ...validParams, audience: undefined }, error: 'audience is required' },
        { params: { ...validParams, subject: undefined }, error: 'subject is required' },
        { params: { ...validParams, address: undefined }, error: 'address is required' },
        { params: { ...validParams, claims: undefined }, error: 'claims is required' }
      ];

      for (const { params, error } of testCases) {
        await expect(script.default.invoke(params, mockContext)).rejects.toThrow(error);
      }
    });

    test('should validate subject JSON format', async () => {
      const invalidParams = {
        ...validParams,
        subject: 'invalid-json'
      };

      await expect(script.default.invoke(invalidParams, mockContext)).rejects.toThrow(
        'Invalid subject JSON'
      );
    });

    test('should validate invalid claims JSON syntax', async () => {
      const invalidParams = {
        ...validParams,
        claims: 'invalid-json'
      };

      await expect(script.default.invoke(invalidParams, mockContext)).rejects.toThrow('Invalid claims JSON');
    });

    test('should require claims to be JSON object', async () => {
      // Test each case individually to ensure each fails at validation stage
      const invalidStringParams = { ...validParams, claims: '"string-value"' };
      await expect(script.default.invoke(invalidStringParams, mockContext)).rejects.toThrow('Claims must be a JSON object');

      const invalidNumberParams = { ...validParams, claims: '123' };
      await expect(script.default.invoke(invalidNumberParams, mockContext)).rejects.toThrow('Claims must be a JSON object');

      const invalidNullParams = { ...validParams, claims: 'null' };
      await expect(script.default.invoke(invalidNullParams, mockContext)).rejects.toThrow('Claims must be a JSON object');

      const invalidArrayParams = { ...validParams, claims: '[]' };
      await expect(script.default.invoke(invalidArrayParams, mockContext)).rejects.toThrow('Claims must be a JSON object');
    });

    test('should accept valid claims JSON objects', async () => {
      const validClaimsExamples = [
        '{"role": "admin"}',
        '{"department": "finance", "clearanceLevel": 3}',
        '{"groups": ["admins", "finance"], "active": true}',
        '{"nested": {"object": {"value": "test"}}}',
        '{}'
      ];

      for (const claims of validClaimsExamples) {
        const params = { ...validParams, claims };
        const result = await script.default.invoke(params, mockContext);
        expect(result.status).toBe('success');
      }
    });

    test('should require SSF_KEY secret', async () => {
      const contextWithoutKey = {
        secrets: {
          SSF_KEY_ID: 'test-key-id'
        }
      };

      await expect(script.default.invoke(validParams, contextWithoutKey)).rejects.toThrow(
        'SSF_KEY secret is required'
      );
    });

    test('should require SSF_KEY_ID secret', async () => {
      const contextWithoutKeyId = {
        secrets: {
          SSF_KEY: mockContext.secrets.SSF_KEY
        }
      };

      await expect(script.default.invoke(validParams, contextWithoutKeyId)).rejects.toThrow(
        'SSF_KEY_ID secret is required'
      );
    });

    test('should handle URL building with suffix', async () => {
      const paramsWithSuffix = {
        ...validParams,
        addressSuffix: '/caep/events'
      };

      await script.default.invoke(paramsWithSuffix, mockContext);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://caep.receiver.com/events/caep/events',
        expect.objectContaining({ headers: expect.any(Object) })
      );
    });

    test('should handle Bearer token prefix', async () => {
      const contextWithBearerToken = {
        secrets: {
          ...mockContext.secrets,
          AUTH_TOKEN: 'Bearer already-prefixed-token'
        }
      };

      await script.default.invoke(validParams, contextWithBearerToken);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://caep.receiver.com/events',
        {
          headers: {
            'Authorization': 'Bearer already-prefixed-token',
            'User-Agent': 'SGNL-Action-Framework/1.0'
          }
        }
      );
    });

    test('should parse i18n reason strings as JSON', async () => {
      const paramsWithI18nReason = {
        ...validParams,
        reasonAdmin: '{"en": "English reason", "es": "Razón en español"}'
      };

      const result = await script.default.invoke(paramsWithI18nReason, mockContext);
      expect(result.status).toBe('success');
    });

    test('should handle plain string reasons', async () => {
      const paramsWithStringReason = {
        ...validParams,
        reasonAdmin: 'Simple string reason'
      };

      const result = await script.default.invoke(paramsWithStringReason, mockContext);
      expect(result.status).toBe('success');
    });

    test('should throw for retryable HTTP errors', async () => {
      const retryableCodes = [429, 502, 503, 504];

      for (const code of retryableCodes) {
        transmitSET.mockRejectedValueOnce(
          new Error(`SET transmission failed: ${code} Error`)
        );

        await expect(script.default.invoke(validParams, mockContext)).rejects.toThrow(
          `SET transmission failed: ${code} Error`
        );
        
        // Reset mock for next iteration
        transmitSET.mockResolvedValue({
          status: 'success',
          statusCode: 200,
          body: '"success"',
          retryable: false
        });
      }
    });

    test('should not throw for non-retryable HTTP errors', async () => {
      transmitSET.mockResolvedValueOnce({
        status: 'failed',
        statusCode: 400,
        body: 'Bad request',
        retryable: false
      });

      const result = await script.default.invoke(validParams, mockContext);

      expect(result.status).toBe('failed');
      expect(result.statusCode).toBe(400);
      expect(result.retryable).toBe(false);
    });

    test('should handle complex claims structures', async () => {
      const complexClaimsParams = {
        ...validParams,
        claims: JSON.stringify({
          role: 'admin',
          permissions: ['read', 'write', 'delete'],
          profile: {
            department: 'IT Security',
            level: 5,
            certifications: ['CISSP', 'CISA']
          },
          activeUntil: '2024-12-31T23:59:59Z'
        })
      };

      const result = await script.default.invoke(complexClaimsParams, mockContext);
      expect(result.status).toBe('success');
    });
  });

  describe('error handler', () => {
    test('should return retry_requested for retryable errors', async () => {
      const retryableErrors = ['429', '502', '503', '504'];

      for (const code of retryableErrors) {
        const params = {
          error: { message: `Error ${code}: Server error` }
        };

        const result = await script.default.error(params, mockContext);
        expect(result).toEqual({ status: 'retry_requested' });
      }
    });

    test('should re-throw non-retryable errors', async () => {
      const testError = new Error('Invalid credentials');
      const params = {
        error: testError
      };

      await expect(script.default.error(params, mockContext)).rejects.toThrow(testError);
    });
  });

  describe('halt handler', () => {
    test('should return halted status', async () => {
      const result = await script.default.halt({}, mockContext);

      expect(result).toEqual({ status: 'halted' });
    });
  });
});