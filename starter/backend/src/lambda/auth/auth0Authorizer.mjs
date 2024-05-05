import Axios from 'axios'
import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'
const logger = createLogger('auth')

const certificate = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJPwW8kG/FtrWJMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi13a2htYXc2ZWE3cTVidmxmLnVzLmF1dGgwLmNvbTAeFw0yNDA1MDUw
MDIwNTdaFw0zODAxMTIwMDIwNTdaMCwxKjAoBgNVBAMTIWRldi13a2htYXc2ZWE3
cTVidmxmLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAMIq3XIYaTOsJ3PmbLNTcdt05qAdgir2B27ZR0ILGEtvFu4vPt6WKlDMavy5
LB09bIJT8r6iMzDrKifM+tLGGEMZdx85UQmwb01dYD5+ijxAimngZIypQiTxCoeC
/sawRIG8xY/gWjMvBgVCOjkrmHZLuvmAEpj4DlATAJn1XDgfx1cF/0MbhVZrIqKf
gj7/0nt+d7MalRPe6xskoV6UgyJLwfO6o5pgtZu5x0dBjPEcJNsl1RN2KVXSAOVp
5gYztSoBhAOlVsQyDLVBOznspHsdMG65SvNtprx0LdkLy7Q8JF4MzHoJ6WgHfPNc
ph0T2sOvCnT4ytQHIBOZ1+6RMtMCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUJ2UPEln6ded18jRGPnvmqTk+ExcwDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQBn0ohBs2yJ4m27odH9VDLAFGEwMS6zL9B/S6h4EVgy
SpqNgnKP3PxQU3b5nzh7bQokzRJ1gRQX1haBekFHj/lRQMcNyOo7hljOI0CPdZwO
VweT7TC/LemoDrJEx0kNNnEqw6S9YZq/QTW7R05oWgRQOAWJ86YbzUxcUaq0ZxDA
JqeaOPUBDJrD2H/d0W8NPLyTh9uQX0VPpzhIQNsVdBVtsP9hujIq85t424yREqgQ
FZBoqNveUToFZv3+rwewqAWl4uNe0wrqFp/IuJyUrFkUjKtHesbuHkhDWjRBIEXq
JDtYQMFwVwChKTMVyJ97Qp9oX+RVkdUx7+BGoZYVFLDZ
-----END CERTIFICATE-----`

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  if (!authHeader) throw new Error('No authorization header')

  if (!authHeader.toLowerCase().startsWith('bearer ')) {
    throw new Error('Invalid authorization header')
  }


  const token = getToken(authHeader)
  const jwt = jsonwebtoken.decode(token, { complete: true })

  return jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] })
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
