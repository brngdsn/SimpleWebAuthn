/**
 * An example Express server showing off a simple integration of @simplewebauthn/server.
 *
 * The webpages served from ./public use @simplewebauthn/browser.
 */

import https from 'https';
import http from 'http';
import fs from 'fs';
import { Pool } from 'pg';
import { ParsedQs } from 'qs';
import express from 'express';
import session from 'express-session';
import memoryStore from 'memorystore';
import dotenv from 'dotenv';

dotenv.config();

declare module 'express-session' {
  interface SessionData {
    loggedInUserId?: string;
    currentChallenge?: string;
    inviteToken?: string | ParsedQs | string[] | ParsedQs[];
  }
}

import {
  // Authentication
  generateAuthenticationOptions,
  // Registration
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  VerifyAuthenticationResponseOpts,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';

import { isoBase64URL, isoUint8Array } from '@simplewebauthn/server/helpers';

import type {
  AuthenticationResponseJSON,
  AuthenticatorDevice,
  RegistrationResponseJSON,
} from '@simplewebauthn/typescript-types';

const pool = new Pool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

const app = express();
const MemoryStore = memoryStore(session);

const {
  ENABLE_CONFORMANCE,
  ENABLE_HTTPS,
  RP_ID,
  SESSION_SECRET,
  INVITE_TOKEN_SECRET,
} = process.env;

import { generateToken, verifyToken } from './helpers'

app.use(express.static('./public/'));
app.use(express.json());
app.use(
  session({
    secret: SESSION_SECRET || 'secret1234',
    saveUninitialized: true,
    resave: false,
    cookie: {
      maxAge: 86400000,
      httpOnly: true, // Ensure to not expose session cookies to clientside scripts
    },
    store: new MemoryStore({
      checkPeriod: 86_400_000, // prune expired entries every 24h
    }),
  }),
);

/**
 * If the words "metadata statements" mean anything to you, you'll want to enable this route. It
 * contains an example of a more complex deployment of SimpleWebAuthn with support enabled for the
 * FIDO Metadata Service. This enables greater control over the types of authenticators that can
 * interact with the Rely Party (a.k.a. "RP", a.k.a. "this server").
 */
if (ENABLE_CONFORMANCE === 'true') {
  import('./fido-conformance').then(
    ({ fidoRouteSuffix, fidoConformanceRouter }) => {
      app.use(fidoRouteSuffix, fidoConformanceRouter);
    },
  );
}

/**
 * RP ID represents the "scope" of websites on which a authenticator should be usable. The Origin
 * represents the expected URL from which registration or authentication occurs.
 */
export const rpID = RP_ID || 'localhost';
// This value is set at the bottom of page as part of server initialization (the empty string is
// to appease TypeScript until we determine the expected origin based on whether or not HTTPS
// support is enabled)
export let expectedOrigin = '';

/**
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs registration or authentication. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the authenticator.
 *
 * Here, the example server assumes the following user has completed login:
 */

/**
 * Registration (a.k.a. "Registration")
 */
app.get('/generate-registration-options', async (req, res) => {
  const username = req.query.username; // Allow users to pick their username
  const inviteToken = req.query.inviteToken; // Get the invite token from the query

  if (!username || !inviteToken) {
    return res.status(400).send({ error: 'Username and invite token are required' });
  }

  // Verify the invite token
  const tokenResult = await pool.query('SELECT * FROM invite_tokens WHERE token = $1 AND used = FALSE', [inviteToken]);
  const token = tokenResult.rows[0];

  if (!token) {
    return res.status(400).send({ error: 'Invalid or already used invite token' });
  }

  // Fetch user from the database using the provided username
  const existingUserResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  const existingUser = existingUserResult.rows[0];

  if (existingUser) {
    return res.status(404).send({ error: 'Username already in use' });
  }

  await pool.query('INSERT INTO users (username) values ($1)', [username]);
  const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = userResult.rows[0];

  req.session.loggedInUserId = user.id;

  // Fetch the devices associated with the user from the database
  const devicesResult = await pool.query('SELECT * FROM devices WHERE user_id = $1', [user.id]);
  const devices = devicesResult.rows;

  const opts: GenerateRegistrationOptionsOpts = {
    rpName: 'ooo-very',
    rpID,
    userID: user.id,
    userName: user.username,
    timeout: 60000,
    attestationType: 'none',
    excludeCredentials: devices.map((dev) => ({
      id: dev.credentialID,
      type: 'public-key',
      transports: JSON.parse(dev.transports), // Assuming transports is stored as a JSON string
    })),
    authenticatorSelection: {
      residentKey: 'discouraged',
    },
    supportedAlgorithmIDs: [-7, -257],
  };

  const options = await generateRegistrationOptions(opts);

  // The server needs to temporarily remember this value for verification
  req.session.currentChallenge = options.challenge;
  req.session.inviteToken = inviteToken;

  res.send(options);
});

app.post('/verify-registration', async (req, res) => {
  const body: RegistrationResponseJSON = req.body;

  const expectedChallenge = req.session.currentChallenge;

  // Fetch the loggedInUserId from the session
  const loggedInUserId = req.session.loggedInUserId;
  const inviteToken = req.session.inviteToken; // Get the invite token from the query

  if (!loggedInUserId) {
    return res.status(400).send({ error: 'User is not logged in' });
  }

  // Fetch the user from the database using the loggedInUserId
  const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [loggedInUserId]);
  const user = userResult.rows[0];

  if (!user) {
    return res.status(404).send({ error: 'User not found' });
  }

  let verification: VerifiedRegistrationResponse;
  try {
    const opts: VerifyRegistrationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    };
    verification = await verifyRegistrationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { credentialPublicKey, credentialID, counter } = registrationInfo;

    // Check if the device already exists in the database for the user
    const existingDeviceResult = await pool.query('SELECT * FROM devices WHERE credentialid = $1 AND user_id = $2', [credentialID, user.id]);

    if (!existingDeviceResult.rows.length) {
      // Insert the new device into the database
      await pool.query(
        'INSERT INTO devices (user_id, credentialpublickey, credentialid, counter, transports) VALUES ($1, $2, $3, $4, $5)',
        [user.id, credentialPublicKey, credentialID, counter, JSON.stringify(body.response.transports)]
      );
    }

    // Mark the token as used
    await pool.query('UPDATE invite_tokens SET used = TRUE WHERE token = $1', [inviteToken]);
  }

  req.session.currentChallenge = undefined;
  req.session.inviteToken = undefined;

  res.send({ verified });
});

/**
 * Login (a.k.a. "Authentication")
 */
app.get('/generate-authentication-options', async (req, res) => {
  const username = req.query.username; // Allow users to pick their username

  if (!username) {
    return res.status(400).send({ error: 'Username is required' });
  }

  // Fetch user from the database using the provided username
  const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = userResult.rows[0];

  if (!user) {
    return res.status(404).send({ error: 'User not found' });
  }

  // Set the loggedInUserId in the session
  req.session.loggedInUserId = user.id;

  // Fetch the devices associated with the user from the database
  const devicesResult = await pool.query('SELECT * FROM devices WHERE user_id = $1', [user.id]);
  const devices = devicesResult.rows;

  const opts: GenerateAuthenticationOptionsOpts = {
    timeout: 60000,
    allowCredentials: devices.map((dev) => ({
      id: dev.credentialid,
      type: 'public-key',
      transports: JSON.parse(dev.transports), // Assuming transports is stored as a JSON string
    })),
    userVerification: 'required',
    rpID,
  };

  const options = await generateAuthenticationOptions(opts);

  // The server needs to temporarily remember this value for verification
  req.session.currentChallenge = options.challenge;

  res.send(options);
});

app.post('/verify-authentication', async (req, res) => {
  const body: AuthenticationResponseJSON = req.body;

  const expectedChallenge = req.session.currentChallenge;

  // Fetch the loggedInUserId from the session
  const loggedInUserId = req.session.loggedInUserId;

  if (!loggedInUserId) {
    return res.status(400).send({ error: 'User is not logged in' });
  }

  // Convert the rawId from the request body to a buffer for comparison
  const bodyCredIDBuffer = isoBase64URL.toBuffer(body.rawId);

  // Fetch the device associated with the credential ID from the database
  const deviceResult = await pool.query('SELECT * FROM devices WHERE credentialid = $1', [bodyCredIDBuffer]);
  const dbAuthenticator = deviceResult.rows[0];

  if (!dbAuthenticator) {
    return res.status(400).send({
      error: 'Authenticator is not registered with this site',
    });
  }

  let verification: VerifiedAuthenticationResponse;

  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: [dbAuthenticator].map((a) => ({ ...a, credentialPublicKey: a.credentialpublickey, credentialId: a.credentialid }))[0],
      requireUserVerification: true,
    };
    verification = await verifyAuthenticationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    // Update the authenticator's counter in the DB to the newest count in the authentication
    await pool.query('UPDATE devices SET counter = $1 WHERE credentialID = $2', [authenticationInfo.newCounter, bodyCredIDBuffer]);
  }

  req.session.currentChallenge = undefined;

  res.send({ verified });
});

if (ENABLE_HTTPS) {
  const host = '0.0.0.0';
  const port = 443;
  expectedOrigin = `https://${rpID}`;

  https
    .createServer(
      {
        /**
         * See the README on how to generate this SSL cert and key pair using mkcert
         */
        key: fs.readFileSync(`./${rpID}.key`),
        cert: fs.readFileSync(`./${rpID}.crt`),
      },
      app,
    )
    .listen(port, host, () => {
      console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
    });
} else {
  const host = '127.0.0.1';
  const port = 8000;
  expectedOrigin = `http://localhost:${port}`;

  http.createServer(app).listen(port, host, () => {
    console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
  });
}
