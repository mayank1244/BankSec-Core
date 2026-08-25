const BANKING_SECURITY_DATA = {
  domains: [
    {
      id: "auth-session",
      name: "Authentication & Session Integrity",
      icon: "fa-user-shield",
      description: "Controls securing user identity, multi-factor authentication, session binding, and token lifecycle in financial applications.",
      controls: [
        {
          id: "AUTH-01",
          name: "Financial-grade OAuth2 / FAPI DPoP Enforcer",
          severity: "CRITICAL",
          asvs: "V2.1 - Level 3",
          pci: "PCI-DSS 8.3",
          fapi: "FAPI 1.0 Advanced",
          description: "Enforce Demonstrating Proof-of-Possession (DPoP) or Mutual TLS (mTLS) client certificates to bind tokens to sender hardware, preventing token theft & replay attacks.",
          remediation: {
            language: "javascript",
            title: "Node.js Express DPoP Verification Middleware",
            code: `const crypto = require('crypto');

function verifyDPoP(req, res, next) {
  const dpopHeader = req.headers['dpop'];
  if (!dpopHeader) {
    return res.status(401).json({ error: 'invalid_dpop', message: 'DPoP proof header required for financial endpoints' });
  }
  
  try {
    // Decode DPoP JWT & verify signature with public key
    const [headerB64, payloadB64, sigB64] = dpopHeader.split('.');
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    
    // Verify HTTP method & URL matching
    const currentUrl = \`\${req.protocol}://\${req.get('host')}\${req.originalUrl}\`;
    if (payload.htm !== req.method || payload.htu !== currentUrl) {
      return res.status(401).json({ error: 'invalid_dpop_proof', message: 'DPoP HTTP method/URL mismatch' });
    }
    
    // Check DPoP proof freshness (max 60 seconds)
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - payload.iat) > 60) {
      return res.status(401).json({ error: 'invalid_dpop_proof', message: 'DPoP token timestamp expired' });
    }
    
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid_dpop', message: err.message });
  }
}`
          }
        },
        {
          id: "AUTH-02",
          name: "Strong Customer Authentication (SCA / PSD2)",
          severity: "CRITICAL",
          asvs: "V2.8 - Level 3",
          pci: "PCI-DSS 8.3.1",
          fapi: "PSD2 RTS Art. 4",
          description: "Require dynamic linking of authentication to specific transfer amounts and recipient account numbers during step-up transaction authorization.",
          remediation: {
            language: "python",
            title: "Python SCA Dynamic Authorization Signer",
            code: `import hmac
import hashlib
import time

def generate_sca_dynamic_link(user_secret: str, amount: float, payee_iban: str, timestamp: int = None) -> str:
    """
    PSD2 Art. 5 compliant Dynamic Linking of authentication code 
    to specific payee & transaction amount.
    """
    if timestamp is None:
        timestamp = int(time.time())
        
    # Payload binds amount + destination IBAN + time window
    payload = f"{amount:.2f}:{payee_iban}:{timestamp}".encode('utf-8')
    
    # Generate 6-digit OTP code tied explicitly to this payload
    digest = hmac.new(user_secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()
    otp_code = str(int(digest[:8], 16) % 1000000).zfill(6)
    return otp_code`
          }
        },
        {
          id: "AUTH-03",
          name: "Strict Session Timeout & Biometric Step-Up",
          severity: "HIGH",
          asvs: "V3.3 - Level 2",
          pci: "PCI-DSS 8.2.6",
          fapi: "NIST 800-63B",
          description: "Enforce automatic session invalidation after 5 minutes of inactivity for banking portals, requiring biometric re-authentication for sensitive actions.",
          remediation: {
            language: "javascript",
            title: "Client-side Inactivity Session Monitor",
            code: `let inactivityTimer;
const INACTIVITY_TIMEOUT = 5 * 60 * 1000; // 5 Minutes

function resetInactivityTimer() {
  clearTimeout(inactivityTimer);
  inactivityTimer = setTimeout(() => {
    // Invalidate auth tokens & redirect to locked screen
    sessionStorage.clear();
    alert("Session expired due to 5 minutes of inactivity. Re-authentication required.");
    window.location.href = "/auth/login?reason=inactivity";
  }, INACTIVITY_TIMEOUT);
}

['mousemove', 'keydown', 'touchstart'].forEach(evt => {
  window.addEventListener(evt, resetInactivityTimer, { passive: true });
});
resetInactivityTimer();`
          }
        }
      ]
    },
    {
      id: "trans-integrity",
      name: "Transaction Security & Anti-Replay",
      icon: "fa-money-bill-transfer",
      description: "Controls protecting fund transfers, API idempotency, non-repudiation, and payload integrity.",
      controls: [
        {
          id: "TXN-01",
          name: "API Request Signing & Anti-Tampering (HMAC-SHA256)",
          severity: "CRITICAL",
          asvs: "V13.2 - Level 3",
          pci: "PCI-DSS 6.4.3",
          fapi: "FAPI 2.0 Security",
          description: "All fund transfer API requests must be cryptographically signed by client app using SHA-256 HMAC or RSA signatures over HTTP headers & body.",
          remediation: {
            language: "java",
            title: "Spring Boot HMAC Request Signature Filter",
            code: `@Component
public class RequestSignatureFilter extends OncePerRequestFilter {

    private static final String HMAC_HEADER = "X-Financial-Signature";
    private static final String TIMESTAMP_HEADER = "X-Financial-Timestamp";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String signature = request.getHeader(HMAC_HEADER);
        String timestamp = request.getHeader(TIMESTAMP_HEADER);

        if (signature == null || timestamp == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing HMAC Financial Signature Headers");
            return;
        }

        // Validate timestamp freshness (+/- 120 seconds)
        long reqTime = Long.parseLong(timestamp);
        if (Math.abs(System.currentTimeMillis() - reqTime) > 120000) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Request signature timestamp expired (Replay Prevention)");
            return;
        }

        filterChain.doFilter(request, response);
    }
}`
          }
        },
        {
          id: "TXN-02",
          name: "Strict Idempotency Keys for Money Transfers",
          severity: "CRITICAL",
          asvs: "V13.1 - Level 3",
          pci: "PCI-DSS 10.2",
          fapi: "ISO 20022",
          description: "Enforce mandatory `Idempotency-Key` header stored in distributed cache (Redis) with atomic locking to prevent duplicate debiting from network retries.",
          remediation: {
            language: "javascript",
            title: "Redis Atomic Idempotency Middleware",
            code: `const redis = require('./redisClient');

async function idempotencyMiddleware(req, res, next) {
  const idempotencyKey = req.headers['idempotency-key'];
  if (!idempotencyKey) {
    return res.status(400).json({ error: 'idempotency_required', message: 'Idempotency-Key header mandatory for financial mutations' });
  }

  const redisKey = \`idempotency:\${idempotencyKey}\`;
  
  // Set lock with 24-hour expiry using SETNX
  const acquired = await redis.set(redisKey, JSON.stringify({ status: 'PROCESSING' }), 'NX', 'EX', 86400);
  
  if (!acquired) {
    const existing = JSON.parse(await redis.get(redisKey));
    if (existing.status === 'PROCESSING') {
      return res.status(409).json({ error: 'concurrent_request', message: 'Transaction already being processed' });
    }
    return res.status(200).json(existing.response); // Return cached response
  }

  req.idempotencyKey = redisKey;
  next();
}`
          }
        },
        {
          id: "TXN-03",
          name: "Dual-Control / 4-Eye Approval for Large Wire Transfers",
          severity: "HIGH",
          asvs: "V1.8 - Level 3",
          pci: "PCI-DSS 7.1",
          fapi: "SOX 404",
          description: "Transactions exceeding threshold limits (e.g. >$50,000) must enter PENDING state requiring separate maker-checker digital approval.",
          remediation: {
            language: "python",
            title: "Python Maker-Checker Approval Workflow",
            code: `def process_transfer_request(maker_id: str, amount: float, recipient: str):
    LIMIT_THRESHOLD = 50000.00
    
    if amount >= LIMIT_THRESHOLD:
        transaction = create_pending_transaction(
            maker_id=maker_id,
            amount=amount,
            recipient=recipient,
            status="PENDING_CHECKER_APPROVAL"
        )
        notify_checker_queue(transaction.id)
        return {"status": "PENDING_APPROVAL", "txn_id": transaction.id, "message": "Transaction requires secondary bank approval"}
        
    return execute_instant_settlement(maker_id, amount, recipient)`
          }
        }
      ]
    },
    {
      id: "pci-data",
      name: "Data Protection & PCI-DSS 4.0 Compliance",
      icon: "fa-vault",
      description: "Controls covering Cardholder Data Environment (CDE), PAN masking, Zero-Trust Storage, and HSM key management.",
      controls: [
        {
          id: "DATA-01",
          name: "Primary Account Number (PAN) Masking & Tokenization",
          severity: "CRITICAL",
          asvs: "V8.1 - Level 3",
          pci: "PCI-DSS 3.4 & 3.5",
          fapi: "EMVCo Tokenization",
          description: "Never store raw 16-digit card numbers in application databases. Retain only BIN (first 6) and last 4 digits; use vault tokenization.",
          remediation: {
            language: "javascript",
            title: "JavaScript Card PAN Tokenization & Masking",
            code: `function maskCardNumber(pan) {
  const cleaned = pan.replace(/\\D/g, '');
  if (cleaned.length < 13 || cleaned.length > 19) {
    throw new Error('Invalid PAN length');
  }
  const first6 = cleaned.substring(0, 6);
  const last4 = cleaned.substring(cleaned.length - 4);
  const maskedMiddle = '*'.repeat(cleaned.length - 10);
  
  return \`\${first6}\${maskedMiddle}\${last4}\`;
}

// Example usage:
// Input: "4532015589128841" -> Output: "453201******8841"`
          }
        },
        {
          id: "DATA-02",
          name: "Hardware Security Module (HSM) Envelope Encryption",
          severity: "CRITICAL",
          asvs: "V8.2 - Level 3",
          pci: "PCI-DSS 3.6 & 3.7",
          fapi: "NIST SP 800-57",
          description: "Encrypt high-value data at rest using AES-256-GCM envelope encryption key hierarchy managed by AWS KMS / Cloud HSM.",
          remediation: {
            language: "python",
            title: "AES-256-GCM Envelope Data Encryption",
            code: `from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class EnvelopeEncryptor:
    @staticmethod
    def encrypt_financial_data(data: bytes, data_encryption_key: bytes) -> dict:
        aesgcm = AESGCM(data_encryption_key)
        nonce = os.urandom(12) # 96-bit initialization vector
        
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return {
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex()
        }

    @staticmethod
    def decrypt_financial_data(ciphertext_hex: str, nonce_hex: str, key: bytes) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ciphertext_hex), None)`
          }
        }
      ]
    },
    {
      id: "api-network",
      name: "API & Open Banking Network Security",
      icon: "fa-network-wired",
      description: "Controls governing API gateways, Mutual TLS, TLS 1.3 ciphers, and Webhook validation.",
      controls: [
        {
          id: "API-01",
          name: "Mutual TLS (mTLS) Certificate Binding for Open Banking",
          severity: "CRITICAL",
          asvs: "V9.1 - Level 3",
          pci: "PCI-DSS 4.1",
          fapi: "FAPI 1.0 Advanced mTLS",
          description: "Enforce client certificate authentication (X.509) issued by approved Qualified Trust Service Providers (QTSP) for third-party providers (TPPs).",
          remediation: {
            language: "javascript",
            title: "Nginx / Express mTLS Client Certificate Validation",
            code: `// Express endpoint extracting verified client cert from reverse proxy (Nginx)
app.use('/open-banking/v3/*', (req, res, next) => {
  const clientCertVerified = req.headers['x-ssl-client-verify'];
  const clientDN = req.headers['x-ssl-client-s-dn'];
  
  if (clientCertVerified !== 'SUCCESS') {
    return res.status(403).json({
      error: 'mtls_required',
      message: 'Valid QTSP X.509 client certificate required for Open Banking APIs'
    });
  }
  
  req.tppIdentity = clientDN;
  next();
});`
          }
        },
        {
          id: "API-02",
          name: "Adaptive Rate Limiting & Anti-Scraping",
          severity: "HIGH",
          asvs: "V13.4 - Level 2",
          pci: "PCI-DSS 6.4.1",
          fapi: "OWASP API Top 10",
          description: "Implement token bucket rate limiting per IP & authenticated account ID to prevent credential stuffing and balance scraping.",
          remediation: {
            language: "python",
            title: "Python Token Bucket Rate Limiter",
            code: `import time

class TokenBucketRateLimiter:
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_update = time.time()

    def allow_request(self) -> bool:
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_update = now

        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False`
          }
        }
      ]
    },
    {
      id: "fraud-monitoring",
      name: "Anti-Fraud & Anomaly Detection Engine",
      icon: "fa-shield-cat",
      description: "Controls for real-time risk assessment, velocity checks, device fingerprinting, and geolocation verification.",
      controls: [
        {
          id: "FRD-01",
          name: "Device Fingerprinting & Risk Score Assessment",
          severity: "HIGH",
          asvs: "V2.10 - Level 3",
          pci: "PCI-DSS 10.6",
          fapi: "PSD2 Risk Engine",
          description: "Capture hardware environment metrics, canvas fingerprints, and IP reputation to assign a dynamic Fraud Risk Index prior to transaction execution.",
          remediation: {
            language: "javascript",
            title: "Fraud Risk Scoring Engine Logic",
            code: `function calculateTransactionRiskScore(ctx) {
  let riskScore = 0; // Range: 0 (Safe) to 100 (High Risk)
  
  // 1. Unrecognized device
  if (!ctx.isKnownDevice) riskScore += 30;
  
  // 2. Geolocation deviation (>500km from last login within 1 hr)
  if (ctx.isImpossibleTravel) riskScore += 45;
  
  // 3. Tor / Proxy / VPN exit node detected
  if (ctx.isProxyOrVpn) riskScore += 25;
  
  // 4. Unusual transaction velocity (3+ transfers in 60s)
  if (ctx.velocityCount > 3) riskScore += 35;
  
  return {
    score: Math.min(riskScore, 100),
    action: riskScore >= 70 ? 'BLOCK_AND_FLAG' : riskScore >= 40 ? 'REQUIRE_SCA_STEPUP' : 'ALLOW'
  };
}`
          }
        }
      ]
    }
  ],

  threatVectors: [
    {
      id: "THREAT-01",
      title: "Transaction Replay & Double-Spending Attack",
      domain: "Transaction Security",
      severity: "CRITICAL",
      description: "An attacker intercepts a legitimate fund transfer HTTP payload and replays it multiple times to debit victim account repeatedly.",
      mitigation: "Enforce single-use Nonce, Request Timestamp validation (+/- 60s), and Redis Idempotency Key locking."
    },
    {
      id: "THREAT-02",
      title: "Open Banking OAuth2 Token Theft via mTLS Bypass",
      domain: "API & Network Security",
      severity: "CRITICAL",
      description: "Malicious entity steals bearer access token and attempts to access financial APIs from unauthorized servers.",
      mitigation: "Mandate FAPI DPoP (Demonstrating Proof of Possession) or mTLS cert-bound access tokens."
    },
    {
      id: "THREAT-03",
      title: "Man-in-the-Middle (MiTM) & Parameter Tampering",
      domain: "Authentication",
      severity: "HIGH",
      description: "Attacker alters destination account IBAN or payment amount in transit.",
      mitigation: "HMAC-SHA256 digital signature over full request body and PSD2 Dynamic Linking during 2FA."
    },
    {
      id: "THREAT-04",
      title: "Primary Account Number (PAN) Exposure in Application Logs",
      domain: "Data Protection",
      severity: "HIGH",
      description: "Raw credit/debit card numbers are logged by web servers during payment processing, violating PCI-DSS.",
      mitigation: "Implement automated payload redaction filters and zero-logging policies for cardholder data."
    }
  ]
};
