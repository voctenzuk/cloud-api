import { createHash, timingSafeEqual } from "crypto";
import { type NextFunction, type Request, type Response } from "express";
import * as jose from "jose";
import { UnauthorizedError } from "./errors";
import { getGoogleOIDCClient } from "./oidc";

const ALLOWED_IDENTITIES = process.env.ALLOWED_IDENTITIES?.split(",")
    .map((identity) => identity.trim().toLowerCase())
    .filter(Boolean);

const getAllowedIdentities = () => {
  if (!ALLOWED_IDENTITIES) return null;
  return ALLOWED_IDENTITIES.length > 0 ? new Set(ALLOWED_IDENTITIES) : null;
};

export const isIdentityAllowed = (identity?: string | null) => {
  const allowedIdentities = getAllowedIdentities();
  const identityNormalized = identity?.trim().toLowerCase();
  if (!allowedIdentities) return true;
  if (!identityNormalized) return false;
  return allowedIdentities.has(identityNormalized);
};

export const verifyToken = async (idToken: string) => {
  const JWKS = jose.createRemoteJWKSet(
    new URL("https://www.googleapis.com/oauth2/v3/certs"),
  );

  try {
    const { payload } = await jose.jwtVerify(idToken, JWKS, {
      issuer: "https://accounts.google.com",
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    return payload;
  } catch  (e) {
    console.error(e);
    return null;
  }
};

/**
 * Refresh the Google id_token using the stored refresh_token.
 * Returns the new id_token if successful, null otherwise.
 */
export const refreshIdToken = async (session: any): Promise<string | null> => {
  const refreshToken = session?.refresh_token;
  if (!refreshToken) {
    console.log("[Auth] No refresh_token in session, cannot refresh");
    return null;
  }

  try {
    console.log("[Auth] Attempting to refresh id_token...");
    const client = await getGoogleOIDCClient();
    const tokenSet = await client.refresh(refreshToken);

    if (tokenSet.id_token) {
      // Update session with fresh tokens
      session.id_token = tokenSet.id_token;
      if (tokenSet.refresh_token) {
        session.refresh_token = tokenSet.refresh_token;
      }
      console.log("[Auth] Successfully refreshed id_token");
      return tokenSet.id_token;
    }

    console.log("[Auth] Refresh did not return a new id_token");
    return null;
  } catch (e) {
    console.error("[Auth] Failed to refresh id_token:", e);
    return null;
  }
};

export const authenticated = async (req: Request, res: Response, next: NextFunction) => {
  let idToken = req.session?.id_token;
  if (!idToken) throw new UnauthorizedError();

  let payload = await verifyToken(idToken);

  // If verification failed (likely expired), try refreshing
  if (!payload && req.session?.refresh_token) {
    const newToken = await refreshIdToken(req.session);
    if (newToken) {
      idToken = newToken;
      payload = await verifyToken(newToken);
    }
  }

  if (!payload) throw new UnauthorizedError();
  if (!payload.exp) throw new UnauthorizedError();

  if (new Date(payload.exp * 1000) < new Date()) {
    throw new UnauthorizedError();
  }

  const email = (payload as { email?: string }).email;
  if (!isIdentityAllowed(email)) {
    throw new UnauthorizedError("Account is not in the allowlist", "account_not_allowed");
  }

  next();
};

const sha256 = (value: string) => createHash("sha256").update(value).digest();

/** Guards a route with one static bearer token, compared in constant time. */
export const bearerToken = (expected: string) => {
  const expectedDigest = sha256(expected);
  return (req: Request, res: Response, next: NextFunction) => {
    // The scheme name is case-insensitive (RFC 9110); the token is not.
    const presented = req.headers.authorization?.match(/^Bearer +(.+)$/i)?.[1];
    if (!presented || !timingSafeEqual(sha256(presented), expectedDigest)) {
      throw new UnauthorizedError("Invalid bearer token");
    }
    next();
  };
};
