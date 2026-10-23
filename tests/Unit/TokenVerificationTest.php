<?php

namespace pmill\AwsCognito\Tests\Unit;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\TestCase;
use pmill\AwsCognito\CognitoClient;
use pmill\AwsCognito\Exception\TokenExpiryException;
use pmill\AwsCognito\Exception\TokenVerificationException;

/**
 * Access/ID token verification on top of web-token/jwt-library 4.
 */
class TokenVerificationTest extends TestCase
{
    private const REGION = 'ap-southeast-1';
    private const USER_POOL_ID = 'ap-southeast-1_TestPool';

    private JWK $key;
    private CognitoClient $client;

    protected function setUp(): void
    {
        $this->key = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'test-key']);

        $this->client = new CognitoClient(new CognitoIdentityProviderClient([
            'region' => self::REGION,
            'version' => '2016-04-18',
            'credentials' => ['key' => 'test', 'secret' => 'test'],
        ]));
        $this->client->setRegion(self::REGION);
        $this->client->setUserPoolId(self::USER_POOL_ID);
        $this->client->setJwtWebKeys(new JWKSet([$this->key->toPublic()]));
    }

    public function testVerifyAccessTokenReturnsUsername(): void
    {
        $this->assertSame('tenant-user', $this->client->verifyAccessToken($this->token(['username' => 'tenant-user'])));
    }

    public function testVerifyIdTokenFallsBackToCognitoUsername(): void
    {
        $token = $this->token(['token_use' => 'id', 'cognito:username' => 'tenant-user']);

        $this->assertSame('tenant-user', $this->client->verifyAccessToken($token));
    }

    public function testDecodeAccessTokenReturnsPayload(): void
    {
        $payload = $this->client->decodeAccessToken($this->token(['username' => 'tenant-user']));

        $this->assertSame('tenant-user', $payload['username']);
        $this->assertSame('access', $payload['token_use']);
    }

    public function testJwksJsonFromCognitoIsParsed(): void
    {
        $json = json_encode(['keys' => [$this->key->toPublic()->all()]]);

        $this->assertCount(1, JWKSet::createFromJson($json)->all());
    }

    public function testExpiredTokenIsRejected(): void
    {
        $this->expectException(TokenExpiryException::class);

        $this->client->verifyAccessToken($this->token(['username' => 'tenant-user', 'exp' => time() - 60]));
    }

    public function testTokenFromAnotherIssuerIsRejected(): void
    {
        $this->expectException(TokenVerificationException::class);

        $this->client->verifyAccessToken($this->token([
            'username' => 'tenant-user',
            'iss' => 'https://cognito-idp.us-east-1.amazonaws.com/other-pool',
        ]));
    }

    public function testTokenWithUnexpectedUseIsRejected(): void
    {
        $this->expectException(TokenVerificationException::class);

        $this->client->verifyAccessToken($this->token(['username' => 'tenant-user', 'token_use' => 'refresh']));
    }

    public function testTokenSignedWithUnknownKeyIsRejected(): void
    {
        $otherKey = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'other-key']);

        $this->expectException(TokenVerificationException::class);

        $this->client->decodeAccessToken($this->token(['username' => 'tenant-user'], $otherKey));
    }

    private function token(array $claims, ?JWK $key = null): string
    {
        $key ??= $this->key;

        $payload = json_encode(array_merge([
            'iss' => sprintf('https://cognito-idp.%s.amazonaws.com/%s', self::REGION, self::USER_POOL_ID),
            'token_use' => 'access',
            'exp' => time() + 3600,
        ], $claims));

        $jws = (new JWSBuilder(new AlgorithmManager([new RS256()])))
            ->create()
            ->withPayload($payload)
            ->addSignature($key, ['alg' => 'RS256', 'kid' => $key->get('kid')])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }
}
