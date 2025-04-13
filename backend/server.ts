import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import dotenv from 'dotenv';
import type {Request, Response} from 'express';

dotenv.config();

const app = express();
app.use(cors());

const keycloakIssuer = `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}`;

const client = jwksClient({
  jwksUri: `${keycloakIssuer}/protocol/openid-connect/certs`,
});

const getKey = (header: jwt.JwtHeader, callback: jwt.SigningKeyCallback) => {
  client.getSigningKey(header.kid!, function (err, key) {
    if (err) {
      callback(err, undefined);
    } else {
      const signingKey = key!.getPublicKey();
      callback(null, signingKey);
    }
  });
}

app.get('/reports', (req: Request, res: Response) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    res.status(403).send('Missing token');
    return;
  }

  jwt.verify(
      token,
      getKey,
      {
        algorithms: ['RS256'],
        issuer: keycloakIssuer,
      },
      (err, decoded) => {
        if (err) {
          console.error('Token verification failed:', err);
          res.status(403).send('Invalid token');
          return;
        }

        const payload = decoded as any;
        const roles = payload.realm_access?.roles || [];

        if (!roles.includes('prothetic_user')) {
          res.status(403).send('Access denied: missing role');
          return;
        }

        res.json({
          "report_id": "BPRO-RPT-20240413-12345",
          "generated_at": "2024-04-13T16:30:00+03:00",
          "user_id": "usr-xyz789",
          "prosthesis_serial": "BPX3-9876",
          "prosthesis_type": "right_arm_advanced",
          "firmware_version": "2.1.4",
          "data_period_start": "2024-04-01",
          "data_period_end": "2024-04-13",
          "total_usage_hours": 142.5,
          "avg_daily_usage": 10.9,
          "avg_response_time_ms": 92,
          "battery_health_percent": 87.5,
          "most_used_gesture": "power_grip",
          "calibration_status": "optimal",
          "last_calibration_date": "2024-04-05",
          "data_sharing_enabled": true,
          "issues_detected": 2
        });
      }
  );
});

app.listen(8000, () => console.log('Server started on port 8000'));
