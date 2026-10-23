<?php

namespace pmill\AwsCognito\Tests\Unit;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Command;
use Aws\MockHandler;
use Aws\Result;
use Faker\Factory;
use Faker\Generator;
use PHPUnit\Framework\TestCase;
use pmill\AwsCognito\CognitoClient;
use pmill\AwsCognito\Exception\ChallengeException;
use pmill\AwsCognito\Exception\CognitoResponseException;
use pmill\AwsCognito\Exception\UserNotFoundException;

class CognitoClientTest extends TestCase
{
    private const APP_CLIENT_ID = 'app_client_id_test';
    private const APP_CLIENT_SECRET = 'app_client_secret_test';
    private const USER_POOL_ID = 'eu-west-1_TestPool';

    private Generator $faker;
    private MockHandler $mock;
    private CognitoClient $cognitoClient;

    protected function setUp(): void
    {
        $this->faker = Factory::create();
        $this->mock = new MockHandler();

        $this->cognitoClient = new CognitoClient(new CognitoIdentityProviderClient([
            'region' => 'eu-west-1',
            'version' => '2016-04-18',
            'credentials' => ['key' => 'key_test', 'secret' => 'secret_test'],
            'handler' => $this->mock,
        ]));
        $this->cognitoClient->setAppClientId(self::APP_CLIENT_ID);
        $this->cognitoClient->setAppClientSecret(self::APP_CLIENT_SECRET);
        $this->cognitoClient->setRegion('eu-west-1');
        $this->cognitoClient->setUserPoolId(self::USER_POOL_ID);
    }

    public function testAuthenticate(): void
    {
        $username = $this->faker->userName();
        $password = $this->faker->password();
        $this->mock->append(new Result(['AuthenticationResult' => ['AccessToken' => 'token']]));

        $result = $this->cognitoClient->authenticate($username, $password);

        $this->assertSame(['AccessToken' => 'token'], $result);
        $command = $this->mock->getLastCommand();
        $this->assertSame('AdminInitiateAuth', $command->getName());
        $this->assertSame('ADMIN_NO_SRP_AUTH', $command['AuthFlow']);
        $this->assertSame([
            'USERNAME' => $username,
            'PASSWORD' => $password,
            'SECRET_HASH' => $this->cognitoSecretHash($username),
        ], $command['AuthParameters']);
        $this->assertSame(self::APP_CLIENT_ID, $command['ClientId']);
        $this->assertSame(self::USER_POOL_ID, $command['UserPoolId']);
    }

    public function testAuthenticateThrowsChallengeException(): void
    {
        $this->mock->append(new Result(['ChallengeName' => 'NEW_PASSWORD_REQUIRED', 'Session' => $this->faker->uuid()]));

        $this->expectException(ChallengeException::class);

        $this->cognitoClient->authenticate('user', 'password');
    }

    public function testAwsErrorsAreMappedToPackageExceptions(): void
    {
        $this->mock->append(fn (Command $command) => new CognitoIdentityProviderException('not found', $command, ['code' => 'UserNotFoundException']));

        try {
            $this->cognitoClient->authenticate('missing', 'password');
            $this->fail('Expected UserNotFoundException');
        } catch (UserNotFoundException $e) {
            $this->assertSame(CognitoResponseException::class, $e->getMessage());
            $this->assertInstanceOf(CognitoIdentityProviderException::class, $e->getPrevious());
        }
    }

    public function testRespondToAuthChallenge(): void
    {
        $session = $this->faker->uuid();
        $responses = ['SMS_MFA_CODE' => '123456', 'USERNAME' => 'user'];
        $this->mock->append(new Result(['AuthenticationResult' => ['AccessToken' => 'token']]));

        $result = $this->cognitoClient->respondToAuthChallenge('SMS_MFA', $responses, $session);

        $this->assertSame(['AccessToken' => 'token'], $result);
        $command = $this->mock->getLastCommand();
        $this->assertSame('RespondToAuthChallenge', $command->getName());
        $this->assertSame('SMS_MFA', $command['ChallengeName']);
        $this->assertSame($responses, $command['ChallengeResponses']);
        $this->assertSame($session, $command['Session']);
    }

    public function testRespondToNewPasswordRequiredChallenge(): void
    {
        $username = $this->faker->userName();
        $newPassword = $this->faker->password();
        $this->mock->append(new Result(['AuthenticationResult' => ['AccessToken' => 'token']]));

        $this->cognitoClient->respondToNewPasswordRequiredChallenge($username, $newPassword, $this->faker->uuid());

        $command = $this->mock->getLastCommand();
        $this->assertSame('NEW_PASSWORD_REQUIRED', $command['ChallengeName']);
        $this->assertSame([
            'NEW_PASSWORD' => $newPassword,
            'USERNAME' => $username,
            'SECRET_HASH' => $this->cognitoSecretHash($username),
        ], $command['ChallengeResponses']);
    }

    public function testRefreshAuthentication(): void
    {
        $username = $this->faker->userName();
        $this->mock->append(new Result(['AuthenticationResult' => ['AccessToken' => 'new-token', 'IdToken' => 'id']]));

        $result = $this->cognitoClient->refreshAuthentication($username, 'refresh-token');

        $this->assertSame(['AccessToken' => 'new-token', 'IdToken' => 'id'], $result);
        $command = $this->mock->getLastCommand();
        $this->assertSame('REFRESH_TOKEN_AUTH', $command['AuthFlow']);
        $this->assertSame('refresh-token', $command['AuthParameters']['REFRESH_TOKEN']);
        $this->assertSame($this->cognitoSecretHash($username), $command['AuthParameters']['SECRET_HASH']);
    }

    private function cognitoSecretHash(string $username): string
    {
        return base64_encode(hash_hmac('sha256', $username . self::APP_CLIENT_ID, self::APP_CLIENT_SECRET, true));
    }
}
