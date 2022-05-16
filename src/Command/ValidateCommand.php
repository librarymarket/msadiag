<?php

declare(strict_types = 1);

namespace LibraryMarket\msadiag\Command;

use Composer\CaBundle\CaBundle;

use LibraryMarket\msadiag\Command\Exception\TestFailureException;
use LibraryMarket\msadiag\SMTP\Auth\CRAMMD5;
use LibraryMarket\msadiag\SMTP\Auth\LOGIN;
use LibraryMarket\msadiag\SMTP\Auth\PLAIN;
use LibraryMarket\msadiag\SMTP\AuthenticationInterface;
use LibraryMarket\msadiag\SMTP\Exception\AuthenticationException;
use LibraryMarket\msadiag\SMTP\Connection;
use LibraryMarket\msadiag\SMTP\ConnectionType;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Validate the supplied SMTP server as a suitable message submission agent.
 */
class ValidateCommand extends Command {

  const SUPPORTED_SASL_MECHANISMS = [
    'CRAM-MD5',
    'LOGIN',
    'PLAIN',
  ];

  /**
   * The type of connection to initiate.
   *
   * @var \LibraryMarket\msadiag\SMTP\ConnectionType
   */
  protected ConnectionType $connectionType = ConnectionType::STARTTLS;

  /**
   * The console input.
   *
   * @var \Symfony\Component\Console\Input\InputInterface
   */
  protected InputInterface $input;

  /**
   * The styled console input/output.
   *
   * @var \Symfony\Component\Console\Style\SymfonyStyle
   */
  protected SymfonyStyle $io;

  /**
   * The console output.
   *
   * @var \Symfony\Component\Console\Output\OutputInterface
   */
  protected OutputInterface $output;

  /**
   * {@inheritdoc}
   */
  protected function configure(): void {
    $this->setName('validate');
    $this->setAliases(['valid']);
    $this->setDescription('Validate the supplied SMTP server as a suitable message submission agent');
    $this->setHelp(\implode("\r\n", [
      'This command connects to the specified SMTP server and validates its suitability for use as a message submission agent.',
      '',
      'A suitable message submission agent must satisfy the following criteria:',
      '',
      ' * The server must not allow authentication via plain-text connection (only with --strict).',
      ' * The server must support a modern TLS encryption protocol (TLSv1.2 or TLSv1.3).',
      ' * The server must use a valid certificate, verifiable using the Mozilla CA bundle.',
      ' * The server must support the SMTP AUTH extension.',
      ' * The server must support SASL authentication via CRAM-MD5, LOGIN, or PLAIN.',
      ' * The server must require authentication to submit messages.',
      ' * The server must reject invalid credentials.',
      ' * The server must accept valid credentials.',
      ' * The server must not require authentication to submit messages after successful authentication.',
    ]));

    $this->addArgument('server-address', InputArgument::REQUIRED, 'The address of the SMTP server');
    $this->addArgument('server-port', InputArgument::REQUIRED, 'The port of the SMTP server');
    $this->addArgument('username', InputArgument::REQUIRED, 'The username to use for authentication');
    $this->addArgument('password', InputArgument::REQUIRED, 'The password to use for authentication');

    $this->addOption('continue-after-failure', NULL, InputOption::VALUE_NONE, 'Run all tests instead of stopping after the first failure');
    $this->addOption('strict', NULL, InputOption::VALUE_NONE, 'Run strict tests in addition to all other tests');
    $this->addOption('tls', NULL, InputOption::VALUE_NONE, 'Use TLS for encryption instead of STARTTLS');
  }

  /**
   * {@inheritdoc}
   */
  protected function execute(InputInterface $input, OutputInterface $output): int {
    $this->io = new SymfonyStyle($input, $output);

    $this->input = $input;
    $this->output = $output;

    if ($this->input->getOption('tls')) {
      $this->connectionType = ConnectionType::TLS;
    }

    $tests = [
      $this->testEncryptionProtocolVersion(...),
      $this->testAuthenticationSupport(...),
      $this->testAuthenticationMechanismSupport(...),
      $this->testAuthenticationIsRequiredForSubmission(...),
      $this->testAuthenticationWithInvalidCredentials(...),
      $this->testAuthenticationWithValidCredentials(...),
    ];

    if ($this->input->getOption('strict')) {
      \array_unshift($tests, $this->testPlainTextAuthenticationIsNotAllowed(...));
    }

    // Run all remaining test cases.
    if (!$this->runTests(...$tests)) {
      return 1;
    }

    $this->output->writeln('');
    $this->output->writeln('<info>The server passed all tests.</info>');

    return 0;
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
    $address = $this->input->getArgument('server-address');
    $port = \intval($this->input->getArgument('server-port'));

    $connection_type ??= $this->connectionType;
    $context = $this->getStreamContext();

    $connection = new Connection($address, $port, $connection_type, $context);

    $connection->connect();
    $connection->probe();

    return $connection;
  }

  /**
   * Get the stream context to use for all connections.
   *
   * @return resource
   *   The stream context to use for all connections.
   */
  protected function getStreamContext() {
    return \stream_context_get_default([
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
    ]);
  }

  /**
   * Run a sequence of tests and return the aggregate result.
   *
   * @param callable ...$tests
   *   A sequence of tests to run.
   *
   * @return bool
   *   TRUE if none of the tests failed, FALSE otherwise.
   */
  protected function runTests(callable ...$tests): bool {
    $result = TRUE;

    foreach ($tests as $test) {
      try {
        $test();
      }
      catch (TestFailureException $e) {
        $result = FALSE;

        if ($message = \preg_split('/\\r?\\n/', $e->getMessage())) {
          $this->io->getErrorStyle()->section('Debug Log');
          foreach ($message as $line) {
            $this->io->getErrorStyle()->writeln("  {$line}");
          }
        }

        if (!$this->input->getOption('continue-after-failure')) {
          break;
        }
      }
    }

    return $result;
  }

  /**
   * Tests if authentication is required to submit messages.
   *
   * @throws \LibraryMarket\msadiag\Command\Exception\TestFailureException
   *   If the test does not succeed.
   */
  protected function testAuthenticationIsRequiredForSubmission(): void {
    $connection = $this->getConnection();
    $this->output->write('Testing if authentication is required to submit messages ... ');

    // Ensure that the server requires authentication to submit messages.
    if (!$connection->isAuthenticationRequired()) {
      $this->output->writeln('<error>FAIL</error>');
      throw new TestFailureException($connection->debug());
    }

    $this->output->writeln('<info>PASS</info>');
  }

  /**
   * Tests if one of CRAM-MD5, LOGIN, or PLAIN are supported.
   *
   * @throws \LibraryMarket\msadiag\Command\Exception\TestFailureException
   *   If the test does not succeed.
   */
  protected function testAuthenticationMechanismSupport(): void {
    $connection = $this->getConnection();
    $this->output->write('Testing if one of CRAM-MD5, LOGIN, or PLAIN are supported ... ');

    // Ensure that the server has at least one of the supported SASL mechanisms.
    $mechanism = \current(\array_intersect($connection->extensions['AUTH'] ?? [], self::SUPPORTED_SASL_MECHANISMS));
    if (!\is_string($mechanism)) {
      $this->output->writeln('<error>FAIL</error>');
      throw new TestFailureException($connection->debug());
    }

    $this->output->writeln('<info>PASS</info>');
  }

  /**
   * Tests if the SMTP AUTH extension is supported.
   *
   * @throws \LibraryMarket\msadiag\Command\Exception\TestFailureException
   *   If the test does not succeed.
   */
  protected function testAuthenticationSupport(): void {
    $connection = $this->getConnection();
    $this->output->write('Testing if the SMTP AUTH extension is supported ... ');

    // Ensure that the server supports the SMTP AUTH extension.
    if (!\array_key_exists('AUTH', $connection->extensions ?? [])) {
      $this->output->writeln('<error>FAIL</error>');
      throw new TestFailureException($connection->debug());
    }

    $this->output->writeln('<info>PASS</info>');
  }

  /**
   * Tests authentication requirements with invalid credentials.
   *
   * @throws \LibraryMarket\msadiag\Command\Exception\TestFailureException
   *   If the test does not succeed.
   */
  protected function testAuthenticationWithInvalidCredentials(): void {
    $connection = $this->getConnection();
    $this->output->write('Testing if authentication fails with invalid credentials ... ');

    try {
      // Retrieve an authentication mechanism with invalid credentials.
      $mechanism = $this->getAuthenticationMechanism($connection->extensions['AUTH'] ?? [], \bin2hex(\random_bytes(8)), \bin2hex(\random_bytes(8)));
    }
    catch (AuthenticationException) {
      // If we reach this point, there are no compatible SASL mechanisms.
      $this->output->writeln('<error>FAIL</error>');
      throw new TestFailureException($connection->debug());
    }

    try {
      // Attempt to authenticate using invalid credentials.
      $connection->authenticate($mechanism);

      // If we reach this point, the server accepted random credentials.
      $this->output->writeln('<error>FAIL</error>');
      throw new TestFailureException($connection->debug());
    }
    catch (AuthenticationException) {
      $this->output->writeln('<info>PASS</info>');
    }
  }

  /**
   * Tests authentication requirements with valid credentials.
   *
   * @throws \LibraryMarket\msadiag\Command\Exception\TestFailureException
   *   If the test does not succeed.
   */
  protected function testAuthenticationWithValidCredentials(): void {
    $connection = $this->getConnection();
    $this->output->write('Testing if authentication succeeds with valid credentials ... ');

    try {
      // Attempt to authenticate using the supplied credentials.
      $connection->authenticate($this->getAuthenticationMechanism($connection->extensions['AUTH'] ?? [], $this->input->getArgument('username'), $this->input->getArgument('password')));
      $this->output->writeln('<info>PASS</info>');
    }
    catch (AuthenticationException) {
      // If we reach this point, the server did not accept our credentials.
      $this->output->writeln('<error>FAIL</error>');
      throw new TestFailureException($connection->debug());
    }

    $this->output->write('Testing if authentication is no longer required to submit messages ... ');

    // Ensure that the server no longer requires authentication.
    if ($connection->isAuthenticationRequired()) {
      $this->output->writeln('<error>FAIL</error>');
      throw new TestFailureException($connection->debug());
    }

    $this->output->writeln('<info>PASS</info>');
  }

  /**
   * Tests if TLSv1.2 or greater is being used.
   *
   * @throws \LibraryMarket\msadiag\Command\Exception\TestFailureException
   *   If the test does not succeed.
   */
  protected function testEncryptionProtocolVersion(): void {
    $connection = $this->getConnection();
    $this->output->write('Testing if TLSv1.2 or greater is being used ... ');

    // Ensure that the server supports a modern encryption protocol.
    $protocol = $connection->getMetadata()['crypto']['protocol'] ?? NULL;
    if (!\is_string($protocol) || \in_array($protocol, ['TLSv1', 'TLSv1.1'])) {
      $this->output->writeln('<error>FAIL</error>');
      throw new TestFailureException($connection->debug());
    }

    $this->output->writeln('<info>PASS</info>');
  }

  /**
   * Tests if authentication is not allowed via plain-text.
   *
   * @throws \LibraryMarket\msadiag\Command\Exception\TestFailureException
   *   If the test does not succeed.
   */
  protected function testPlainTextAuthenticationIsNotAllowed(): void {
    if ($this->connectionType !== ConnectionType::TLS) {
      $connection = $this->getConnection(ConnectionType::PlainText);
      $this->output->write('Testing if authentication is not allowed via plain-text ... ');

      if (\array_key_exists('AUTH', $connection->extensions ?? [])) {
        $this->output->writeln('<error>FAIL</error>');
        throw new TestFailureException($connection->debug());
      }

      $this->output->writeln('<info>PASS</info>');
    }
  }

}
