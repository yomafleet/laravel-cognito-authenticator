<?php

namespace Yomafleet\CognitoAuthenticator;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use CoderCat\JWKToPEM\JWKConverter;
use Yomafleet\CognitoAuthenticator\Factories\TokenFactory;
use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;
use Yomafleet\CognitoAuthenticator\Contracts\DecoderContract;
use Yomafleet\CognitoAuthenticator\Exceptions\UnknownException;
use Yomafleet\CognitoAuthenticator\Exceptions\InvalidJwkException;
use Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract;
use Yomafleet\CognitoAuthenticator\Contracts\ClaimVerifierContract;
use Yomafleet\CognitoAuthenticator\Exceptions\InvalidStructureException;
use Yomafleet\CognitoAuthenticator\Exceptions\ExpiredException as JuhwitExpiredException;

/**
 * @see https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
 */
class JwtDecoder implements DecoderContract
{
    /**
     * @var ClaimVerifierContract
     */
    protected $verifier;

    /**
     * @var array<string>
     */
    protected $requiredClaims;

    /**
     * @var TokenFactoryContract
     */
    protected $tokenFactory;

    /**
     * JwtDecoder constructor.
     *
     * @param  ClaimVerifierContract  $verifier
     * @param  TokenFactoryContract  $tokenFactory
     */
    public function __construct(
        ClaimVerifierContract $verifier,
        TokenFactoryContract $tokenFactory = null
    ) {
        $this->verifier = $verifier;
        $this->tokenFactory = $tokenFactory ?? new TokenFactory();
    }

    /**
     * {@inheritdoc}
     *
     * @param  string  $token
     * @param  array<string>  $requiredClaims
     * @return TokenContract
     *
     * @throws TeamGantt\Api\Exceptions\Token\InvalidClaimsException
     */
    public function decode(string $token, array $requiredClaims = []): TokenContract
    {
        [$header] = $this->validateStructure($token);
        $headerData = json_decode($header, true);
        $kid = $headerData['kid'];
        $claims = $this->getVerifiedToken($kid, $token);
        $token = $this->tokenFactory->create($claims, $requiredClaims);

        return $this->verifier->verify($token);
    }

    /**
     * Get the key that was used to sign the token.
     *
     * @param  string  $keyId
     * @param  string  $jwkFile
     * @return null|array
     */
    private function getKey(string $keyId)
    {
        // Get the key that was used to sign the token
        $jwk = $this->verifier->getUserPool()->getJwk();
        $keys = $jwk['keys'] ?? [];

        return array_reduce($keys, function ($signingKey, $current) use ($keyId) {
            if ($current['kid'] === $keyId) {
                return $current;
            }

            return $signingKey;
        });
    }

    /**
     * Verify and return token.
     *
     * @param  string  $keyId
     * @param  string  $jwkFile
     * @param  string  $token
     * @return array
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\ExpiredException
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\InvalidJwkException
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\UnknownException
     */
    private function getVerifiedToken(string $keyId, string $token): array
    {
        $key = $this->getKey($keyId);

        if (empty($key)) {
            throw new InvalidJwkException("Could not locate key with ID $keyId");
        }

        // Convert the JWK to a PEM for use with JWT::decode
        $converter = new JWKConverter();
        $pem = $converter->toPEM($key);

        // Return the decoded token
        try {
            $alg = $key['alg'];

            return (array) JWT::decode($token, new Key($pem, $alg));
        } catch (ExpiredException $e) {
            throw new JuhwitExpiredException($e->getMessage(), $e->getCode(), $e);
        } catch (\Exception $e) {
            throw new UnknownException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Verify the token has the structure we are expecting.
     *
     * @param  string  $token
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\InvalidStructureException
     */
    private function validateStructure(string $token): array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new InvalidStructureException('Token requires 3 parts delimited by periods');
        }

        $decoded = array_map(function ($part) {
            // base64 url decode
            $b64 = strtr($part, '-_', '+/');

            return base64_decode($b64, true);
        }, $parts);

        $i = 0;
        foreach ($decoded as $part) {
            $i++;
            if (empty($part)) {
                throw new InvalidStructureException("Token part $i not Base64url encoded");
            }
        }

        return $decoded;
    }
}
