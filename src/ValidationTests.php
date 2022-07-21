<?php

declare(strict_types = 1);

namespace LibraryMarket\msadiag;

use Composer\CaBundle\CaBundle;

use LibraryMarket\msadiag\Attribute\ValidationTest;
use LibraryMarket\msadiag\Exception\TestFailureException;
use LibraryMarket\msadiag\SMTP\Auth\CRAMMD5;
use LibraryMarket\msadiag\SMTP\Auth\LOGIN;
use LibraryMarket\msadiag\SMTP\Auth\PLAIN;
use LibraryMarket\msadiag\SMTP\AuthenticationInterface;
use LibraryMarket\msadiag\SMTP\Exception\AuthenticationException;
use LibraryMarket\msadiag\SMTP\Connection;
use LibraryMarket\msadiag\SMTP\ConnectionType;

/**
 * Validation test cases for message submission agent suitability.
 */
class ValidationTests {

  const SUPPORTED_SASL_MECHANISMS = [
    'CRAM-MD5',
    'LOGIN',
    'PLAIN',
  ];

  /**
   * The IP address or hostname of the message submission agent.
   *
   * @var string
   */
  protected $address;

  /**
   * The type of connection to establish to the message submission agent.
   *
   * @var \LibraryMarket\msadiag\SMTP\ConnectionType
   */
  protected ConnectionType $connectionType = ConnectionType::STARTTLS;

  /**
   * The password to use for authentication.
   *
   * @var string
   */
  protected $password;

  /**
   * The port used by the message submission agent.
   *
   * @var int
   */
  protected $port;

  /**
   * TRUE if strict tests should be ran, FALSE otherwise (default: FALSE).
   *
   * @var bool
   */
  protected $runStrictTests;

  /**
   * The sender address to use for checking authentication (default: '').
   *
   * @var string
   */
  protected $sender;

  /**
   * The username to use for authentication.
   *
   * @var string
   */
  protected $username;

  /**
   * Constructs a ValidationTests object.
   *
   * @param string $address
   *   The IP address or hostname of the message submission agent.
   * @param int $port
   *   The port used by the message submission agent.
   * @param bool $use_tls
   *   Whether to use TLS instead of STARTTLS for testing.
   * @param string $username
   *   The username to use for authentication.
   * @param string $password
   *   The password to use for authentication.
   * @param bool $run_strict_tests
   *   TRUE if strict tests should be ran, FALSE otherwise (default: FALSE).
   * @param string $sender
   *   The sender address to use for checking authentication (default: '').
   */
  public function __construct(string $address, int $port, bool $use_tls, string $username, string $password, bool $run_strict_tests = FALSE, string $sender = '') {
    $this->address = $address;
    $this->port = $port;
    $this->username = $username;
    $this->password = $password;
    $this->runStrictTests = $run_strict_tests;
    $this->sender = $sender;

    if ($use_tls) {
      $this->connectionType = ConnectionType::TLS;
    }
  }

  /**
   * Get a compatible authentication mechanism using the supplied credentials.
   *
   * @param string[] $mechanisms
   *   A list of SASL mechanisms supported by the remote server.
   * @param string $username
   *   The username to use for authentication.
   * @param string $password
   *   The password to use for authentication.
   *
   * @throws \LibraryMarket\msadiag\SMTP\Exception\AuthenticationException
   *   If unable to find a matching SASL mechanism for authentication.
   *
   * @return \LibraryMarket\msadiag\SMTP\AuthenticationInterface
   *   A compatible authentication mechanism using the supplied credentials.
   */
  protected function getAuthenticationMechanism(array $mechanisms, string $username, string $password): AuthenticationInterface {
    try {
      return match (\current(\array_intersect(self::SUPPORTED_SASL_MECHANISMS, $mechanisms))) {
        'CRAM-MD5' => new CRAMMD5($username, $password),
        'LOGIN' => new LOGIN($username, $password),
        'PLAIN' => new PLAIN($username, $password),
      };
    }
    catch (\UnhandledMatchError) {
      throw new AuthenticationException('Unable to find a matching SASL mechanism for authentication');
    }
  }

  /**
   * Get a new connection to the remote server.
   *
   * @param \LibraryMarket\msadiag\SMTP\ConnectionType|null $connection_type
   *   An optional connection type override, or NULL (default: NULL).
   *
   * @return \LibraryMarket\msadiag\SMTP\Connection
   *   A connection to the remote server.
   */
  protected function getConnection(?ConnectionType $connection_type = NULL): Connection {
    $connection_type ??= $this->connectionType;

    $connection = new Connection($this->address, $this->port, $connection_type);
    $connection->setStreamContext(\stream_context_get_default([
      'ssl' => [
        'SNI_enabled' => TRUE,
        'allow_self_signed' => FALSE,
        'cafile' => CaBundle::getBundledCaBundlePath(),
        'capath' => \dirname(CaBundle::getBundledCaBundlePath()),
        'crypto_method' => \STREAM_CRYPTO_METHOD_TLS_CLIENT,
        'disable_compression' => TRUE,
        'verify_peer' => TRUE,
        'verify_peer_name' => TRUE,
      ],
    ]));

    $connection->connect();
    $connection->probe();

    return $connection;
  }

  /**
   * Generate a list of callable test methods keyed by description.
   *
   * @return \Generator
   *   A list of callable test methods keyed by description.
   */
  public function getTests(): \Generator {
    $reflection = new \ReflectionClass($this);

    foreach ($reflection->getMethods() as $method) {
      $attributes = $method->getAttributes(ValidationTest::class);

      foreach ($attributes as $attribute) {
        $test = $attribute->newInstance();

        if (!$test->strict || $this->runStrictTests) {
          yield $test->description => $this->{$method->getName()}(...);
          break;
        }
      }
    }
  }

  /**
   * Test if authentication is not allowed via plain-text.
   *
   * @throws \LibraryMarket\msadiag\Exception\TestFailureException
   *   If the test does not succeed.
   */
  #[ValidationTest('Test if authentication is not allowed via plain-text', TRUE)]
  protected function testPlainTextAuthenticationIsNotAllowed(): void {
    if ($this->connectionType !== ConnectionType::TLS) {
      $connection = $this->getConnection(ConnectionType::PlainText);

      if (\array_key_exists('AUTH', $connection->extensions ?? [])) {
        throw new TestFailureException($connection->debug());
      }
    }
  }

  /**
   * Test if TLSv1.2 or greater is being used.
   *
   * @throws \LibraryMarket\msadiag\Exception\TestFailureException
   *   If the test does not succeed.
   */
  #[ValidationTest('Test if TLSv1.2 or greater is being used')]
  protected function testEncryptionProtocolVersion(): void {
    $connection = $this->getConnection();

    // Ensure that the server supports a modern encryption protocol.
    $protocol = $connection->getMetadata()['crypto']['protocol'] ?? NULL;
    if (!\is_string($protocol) || \in_array($protocol, ['TLSv1', 'TLSv1.1'])) {
      throw new TestFailureException($connection->debug());
    }
  }

  /**
   * Test if the SMTP AUTH extension is supported.
   *
   * @throws \LibraryMarket\msadiag\Exception\TestFailureException
   *   If the test does not succeed.
   */
  #[ValidationTest('Test if the SMTP AUTH extension is supported')]
  protected function testAuthenticationSupport(): void {
    $connection = $this->getConnection();

    // Ensure that the server supports the SMTP AUTH extension.
    if (!\array_key_exists('AUTH', $connection->extensions ?? [])) {
      throw new TestFailureException($connection->debug());
    }
  }

  /**
   * Test if one of CRAM-MD5, LOGIN, or PLAIN are supported.
   *
   * @throws \LibraryMarket\msadiag\Exception\TestFailureException
   *   If the test does not succeed.
   */
  #[ValidationTest('Test if one of CRAM-MD5, LOGIN, or PLAIN are supported')]
  protected function testAuthenticationMechanismSupport(): void {
    $connection = $this->getConnection();

    // Ensure that the server has at least one of the supported SASL mechanisms.
    $mechanism = \current(\array_intersect($connection->extensions['AUTH'] ?? [], self::SUPPORTED_SASL_MECHANISMS));
    if (!\is_string($mechanism)) {
      throw new TestFailureException($connection->debug());
    }
  }

  /**
   * Test if authentication is required to submit messages.
   *
   * @throws \LibraryMarket\msadiag\Exception\TestFailureException
   *   If the test does not succeed.
   */
  #[ValidationTest('Test if authentication is required to submit messages')]
  protected function testAuthenticationIsRequiredForSubmission(): void {
    $connection = $this->getConnection();

    // Ensure that the server requires authentication to submit messages.
    if (!$connection->isAuthenticationRequired($this->sender)) {
      throw new TestFailureException($connection->debug());
    }
  }

  /**
   * Test if authentication fails with invalid credentials.
   *
   * @throws \LibraryMarket\msadiag\Exception\TestFailureException
   *   If the test does not succeed.
   */
  #[ValidationTest('Test if authentication fails with invalid credentials')]
  protected function testAuthenticationWithInvalidCredentials(): void {
    $connection = $this->getConnection();

    try {
      // Retrieve an authentication mechanism with invalid credentials.
      $mechanism = $this->getAuthenticationMechanism($connection->extensions['AUTH'] ?? [], \bin2hex(\random_bytes(8)), \bin2hex(\random_bytes(8)));
    }
    catch (AuthenticationException) {
      // If we reach this point, there are no compatible SASL mechanisms.
      throw new TestFailureException($connection->debug());
    }

    try {
      // Attempt to authenticate using invalid credentials.
      $connection->authenticate($mechanism);

      // If we reach this point, the server accepted random credentials.
      throw new TestFailureException($connection->debug());
    }
    catch (AuthenticationException) {
    }
  }

  /**
   * Test if message submission is allowed after successful authentication.
   *
   * @throws \LibraryMarket\msadiag\Exception\TestFailureException
   *   If the test does not succeed.
   */
  #[ValidationTest('Test if message submission is allowed after successful authentication')]
  protected function testSubmissionAfterSuccessfulAuthentication(): void {
    $connection = $this->getConnection();

    try {
      // Attempt to authenticate using the supplied credentials.
      $connection->authenticate($this->getAuthenticationMechanism($connection->extensions['AUTH'] ?? [], $this->username, $this->password));
    }
    catch (AuthenticationException) {
      // If we reach this point, the server did not accept our credentials.
      throw new TestFailureException($connection->debug());
    }

    // Ensure that the server no longer requires authentication.
    if ($connection->isAuthenticationRequired($this->sender)) {
      throw new TestFailureException($connection->debug());
    }
  }

}
