import * as v from 'valibot';

const ExpSchema = v.pipe(
  v.number(),
  // check minValue
  v.custom((input: unknown) => {
    const now = new Date(); // in millisec
    const exp = (input as number) * 1000; // input is in sec
    return now.getTime() < exp;
  }, 'key has expired'),
  // check maxValue
  v.custom((input: unknown) => {
    const limit = new Date(); // limit is in millisec
    limit.setTime(limit.getTime() + Number(process.env.TSDOWN_PUBLIC_KEY_MAX_LIFETIME_MILLISEC));
    const exp = (input as number) * 1000; // input is in sec
    return exp < limit.getTime();
  }, 'key expiry is too far in the future'),
);
const RequestUriSchema = v.pipe(
  v.string(),
  v.custom((input: unknown) => URL.canParse(input as string, 'https://bizkit.io')),
  v.length(Number(process.env.TSDOWN_URL_LENGTH), 'bad request url'),
);
const RedeemUrlSchema = v.pipe(
  v.string(),
  v.custom((input: unknown) => URL.canParse(input as string, 'https://bizkit.io')),
);
const PublicKeySchema = v.pipe(
  v.string(),
  v.length(Number(process.env.TSDOWN_PUBLIC_KEY_LENGTH), 'bad public key'),
  v.custom((input: unknown) => {
    if (typeof input !== 'string') return false;
    if (input.length % 4 === 1) return false;
    return /^[A-Za-z0-9_-]+$/.test(input); // base64url
  }),
);

const IssuerDirectorySchema = v.object({
  exp: ExpSchema,
  'issuer-request-uri': RequestUriSchema,
  'redeem-url': RedeemUrlSchema,
  'token-key': PublicKeySchema,
});

export const IssuerDirectoryWrapperSchema = v.object({
  'token-keys': v.pipe(v.array(IssuerDirectorySchema), v.minLength(1)),
});

export type IssuerDirectory = v.InferOutput<typeof IssuerDirectorySchema>;
export type IssuerDirectoryWrapper = v.InferOutput<typeof IssuerDirectoryWrapperSchema>;

export type BizkitToken = {
  token: string;
  redeem_url: string;
};
