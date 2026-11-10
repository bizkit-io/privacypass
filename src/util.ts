import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { encode } from 'quicvarint';
import * as v from 'valibot';
import { IssuerDirectoryWrapperSchema, type IssuerDirectory, type BizkitToken } from './types';

// ristretto255
const TOKEN_TYPE = new Uint8Array([0, 5]);

async function getPublicKeys(serverUrl: string): Promise<IssuerDirectory[]> {
  const resp = await fetch(`${serverUrl}/api/user/.well-known/private-token-issuer-directory`, {
    mode: 'cors',
    headers: {
      Accept: 'application/json',
    },
  });
  const jsonRaw = await resp.json();
  const parsed = v.parse(IssuerDirectoryWrapperSchema, jsonRaw);
  return parsed['token-keys'];
}

export async function getServer(serverUrl: string) {
  const keys = await getPublicKeys(serverUrl);
  const server = keys[0]; // TODO
  const public_key = Uint8Array.fromBase64(server['token-key'], {
    alphabet: 'base64url',
  });

  return {
    public_key,
    keyId: sha256(public_key),
    issue_url: new URL(server['issuer-request-uri'], serverUrl).toString(),
    redeem_url: new URL(server['redeem-url'], serverUrl).toString(),
  };
}

export function getChallengeDigest(issuer: string, origin: string): Uint8Array {
  const issuerName = utf8ToBytes(issuer);
  const originInfo = utf8ToBytes(origin);
  const redemptionContext = new Uint8Array();
  const bytes = concatBytes(
    TOKEN_TYPE,
    encode(issuerName.length, 2),
    issuerName,
    encode(redemptionContext.length, 2),
    redemptionContext,
    encode(originInfo.length, 2),
    originInfo,
  );
  return sha256(bytes);
}

function truncatedKeyId(keyId: Uint8Array): number {
  return keyId.at(-1)!;
}

export function tokenInputFromChallenge(nonce: Uint8Array, challengeDigest: Uint8Array, keyId: Uint8Array): Uint8Array {
  return concatBytes(TOKEN_TYPE, nonce, challengeDigest, keyId);
}

export function createTokenRequest(keyId: Uint8Array, blinded: Uint8Array): Uint8Array {
  if (blinded.length !== Number(process.env.TSDOWN_EXPECTED_BLIND_SIZE)) {
    throw new Error('blinded size is wrong: ' + blinded.length);
  }
  return concatBytes(TOKEN_TYPE, new Uint8Array([truncatedKeyId(keyId)]), new Uint8Array([blinded.length]), blinded);
}

export async function server_issue_token(issue_url: string, request_body: Uint8Array): Promise<Uint8Array> {
  const result = await fetch(issue_url, {
    method: 'POST',
    mode: 'cors',
    headers: {
      Accept: 'application/private-token-response',
      'Content-Type': 'application/private-token-request',
    },
    credentials: 'include',
    body: request_body as BodyInit,
  });

  if (result.status !== 200) throw new Error('error from server: ' + result.status);

  const response_body = new Uint8Array(await result.arrayBuffer());
  if (response_body.byteLength !== Number(process.env.TSDOWN_EXPECTED_RESULT_SIZE)) {
    throw new Error('bad response size: ' + response_body.byteLength);
  }

  return response_body;
}

export function generate_bizkit_token(
  nonce: Uint8Array,
  challenge_digest: Uint8Array,
  keyId: Uint8Array,
  authenticator: Uint8Array,
  redeem_url: string,
): BizkitToken {
  const token_binary = concatBytes(TOKEN_TYPE, nonce, challenge_digest, keyId, authenticator);
  const token = token_binary.toBase64({ alphabet: 'base64url' });

  return {
    token,
    redeem_url,
  } satisfies BizkitToken;
}
