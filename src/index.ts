import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { randomBytes } from '@noble/hashes/utils.js';

import {
  getServer,
  getChallengeDigest,
  tokenInputFromChallenge,
  createTokenRequest,
  server_issue_token,
  generate_bizkit_token,
} from './util';
import { type BizkitToken } from './types';

export type { BizkitToken };

const voprf = ristretto255_oprf.voprf;

export async function get_token(origin: string, server: string): Promise<BizkitToken> {
  const { public_key, keyId, issue_url, redeem_url } = await getServer(server);

  const nonce = randomBytes(32);
  const challenge_digest = getChallengeDigest('bizkit.io', origin);
  const token_input = tokenInputFromChallenge(nonce, challenge_digest, keyId);
  const blind = voprf.blind(token_input);
  const token_request = createTokenRequest(keyId, blind.blinded);

  const token_reponse = await server_issue_token(issue_url, token_request);

  const authenticator = voprf.finalize(
    token_input,
    blind.blind,
    token_reponse.slice(1, 33),
    blind.blinded,
    public_key,
    token_reponse.slice(33, 97),
  );

  return generate_bizkit_token(nonce, challenge_digest, keyId, authenticator, redeem_url);
}
