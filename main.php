<?php

require_once 'vendor/autoload.php';

use Symfony\Component\Security\Core\Authentication\AuthenticationProviderManager;
use Symfony\Component\Security\Core\Authentication\Provider\DaoAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\Voter\RoleVoter;
use Symfony\Component\Security\Core\Encoder\EncoderFactory;
use Symfony\Component\Security\Core\Encoder\PlaintextPasswordEncoder;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserChecker;

/**
 * AUTHENTICATION
 */

// The user provider represents a source of user information. This could be a database table, a REST API or some other
// mechanism which lets us query for a user based on an identifier (the username).
$userProvider = new InMemoryUserProvider([
    'marco' => [
        'password' => 'p4$$w0rd',
        // Roles are absolutely key here. Symfony follows a simple rule with regards to tokens:
        // - A token without roles is unauthenticated.
        // - A token with roles is authenticated.
        // If you leave this out, Symfony won't notice and won't complain. But a successful authentication
        // will return an unauthenticated token.
        'roles' => ['ROLE_USER'],
    ],
]);

// The user checker provides hooks that let you check the user before authentication and after authentication.
// The default implementation checks for the following:
// - Pre-Auth: if the user (fetched from the DB) is disabled, locked or expired.
// - Post-Auth: if the user's (who we know gave the correct password) credentials have expired, even though they are correct.
$userChecker = new UserChecker();

// Given an object representing a user, the encoder factory returns the correct password encoder to use for checking
// if the password matches.
// It also has the ability to accept config parameters and create the password encoder instance.
$encoderFactory = new EncoderFactory([
    User::class => new PlaintextPasswordEncoder(),
]);

// This is used to figure out which authentication provider to use for any given token. The provider key on the provider must
// match the provider key on the token.
const PROVIDER_KEY = 'default';

// As implied above, the authentication provider manager (the authentication manager based on providers) can contain multiple
// authenticaton providers.
// The second argument is a boolean. Setting it to false (its default value is true) will mean that sensitive information
// (like credentials) will not be erased from the authentication token.
$authenticationManager = new AuthenticationProviderManager([
    new DaoAuthenticationProvider($userProvider, $userChecker, PROVIDER_KEY, $encoderFactory),
]);

// The unauthenticated token. This is what user input gets transformed to.
$token = new UsernamePasswordToken('marco', 'p4$$w0rd', PROVIDER_KEY);

// The authenticated token.
$token = $authenticationManager->authenticate($token);

echo sprintf(
    'AUTHENTICATION = username: %s, authenticated: %s, credentials: %s'.PHP_EOL,
    $token->getUsername(),
    $token->isAuthenticated(),
    $token->getCredentials()
);

/**
 * AUTHORIZATION
 */

// The access decision manager uses security voters to determine whether a user is allowed to access a resource or not.
// By default, the affirmative access decision strategy is used, meaning that access is granted if one or more voters
// return true.
$accessDecisionManager = new AccessDecisionManager([
    // Usually the attribute to check for would represent the action being executed, with the subject being was is acted upon.
    // Symfony also uses this mechanism to check for roles, in which case the subject is ignored.
    // Roles are strings that begin with a certain prefix (ROLE_ by default).
    // The RoleVoter will check if the user has been assigned at least one of the given roles.
    new RoleVoter(),
]);

// The second argument (attributes) must be an array of strings.
// The third argument (subject) is optional and null by default.
$isUser = $accessDecisionManager->decide($token, ['ROLE_USER']);

echo "AUTHORIZATION = isUser: $isUser".PHP_EOL;

