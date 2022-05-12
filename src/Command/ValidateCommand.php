<?php

namespace LibraryMarket\mstt\Command;

use Composer\CaBundle\CaBundle;

use LibraryMarket\mstt\SMTP\Auth\CRAMMD5;
use LibraryMarket\mstt\SMTP\Auth\LOGIN;
use LibraryMarket\mstt\SMTP\Auth\PLAIN;
use LibraryMarket\mstt\SMTP\AuthenticationInterface;
use LibraryMarket\mstt\SMTP\Exception\AuthenticationException;
use LibraryMarket\mstt\SMTP\Exception\ConnectException;
use LibraryMarket\mstt\SMTP\Exception\CryptoException;
use LibraryMarket\mstt\SMTP\Connection;
use LibraryMarket\mstt\SMTP\ConnectionType;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

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
   * The current connection.
   *
   * @var \LibraryMarket\mstt\SMTP\Connection
   */
  protected Connection $connection;

  /**
   * The type of connection to initiate.
   *
   * @var \LibraryMarket\mstt\SMTP\ConnectionType
   */
  protected ConnectionType $connectionType = ConnectionType::STARTTLS;

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
      ' * The server must not allow authentication via plain-text connection.',
      ' * The server must support a modern TLS encryption protocol (TLSv1.2 or TLSv1.3).',
      ' * The server must use a valid certificate, verifiable using the Mozilla CA bundle.',
      ' * The server must support the SMTP AUTH extension.',
      ' * The server must support SASL authentication via CRAM-MD5, LOGIN, or PLAIN.',
      ' * The server must reject invalid credentials.',
      ' * The server must require authentication to submit messages.',
      ' * The server must accept valid credentials.',
      ' * The server must not require authentication to submit messages after successful authentication.',
    ]));

    $this->addArgument('server-address', InputArgument::REQUIRED, 'The address of the SMTP server');
    $this->addArgument('server-port', InputArgument::REQUIRED, 'The port of the SMTP server');
    $this->addArgument('username', InputArgument::REQUIRED, 'The username to use for authentication');
    $this->addArgument('password', InputArgument::REQUIRED, 'The password to use for authentication');

    $this->addOption('tls', NULL, InputOption::VALUE_NONE, 'Use TLS for encryption instead of STARTTLS');
  }

  /**
   * {@inheritdoc}
   */
  protected function execute(InputInterface $input, OutputInterface $output): int {
    if ($input->getOption('tls')) {
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

    // Run all remaining test cases.
    if (!$this->runTests($input, $output, ...$tests)) {
      return Command::FAILURE;
    }

    $output->writeln('');
    $output->writeln('<info>The server passed all tests.</info>');

    return Command::SUCCESS;
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
   * @throws \RuntimeException
   *   If unable to find a matching SASL mechanism for authentication.
   *
   * @return \LibraryMarket\mstt\SMTP\AuthenticationInterface|null
   *   An authentication mechanism, or NULL if there is no compatible mechanism.
   */
  protected function getAuthenticationMechanism(array $mechanisms, string $username, string $password): ?AuthenticationInterface {
    try {
      return match (\current(\array_intersect(self::SUPPORTED_SASL_MECHANISMS, $mechanisms))) {
        'CRAM-MD5' => new CRAMMD5($username, $password),
        'LOGIN' => new LOGIN($username, $password),
        'PLAIN' => new PLAIN($username, $password),
      };
    }
    catch (\UnhandledMatchError) {
      throw new \RuntimeException('Unable to find a matching SASL mechanism for authentication');
    }
  }

  /**
   * Get a new connection to the remote server.
   *
   * @return \LibraryMarket\mstt\SMTP\Connection
   *   A connection to the remote server.
   */
  protected function getConnection(InputInterface $input) {
    $connection = new Connection($input->getArgument('server-address'), $input->getArgument('server-port'), $this->connectionType, $this->getStreamContext());

    try {
      $connection->connect();
      $connection->probe();
    }
    catch (ConnectException | CryptoException) {
    }

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
   * @param \Symfony\Component\Console\Input\InputInterface $input
   *   The console input.
   * @param \Symfony\Component\Console\Output\OutputInterface $output
   *   The console output.
   * @param callable ...$tests
   *   A sequence of tests to run.
   *
   * @return bool
   *   TRUE if none of the tests failed, FALSE otherwise.
   */
  protected function runTests(InputInterface $input, OutputInterface $output, callable ...$tests): bool {
    foreach ($tests as $test) {
      if (!$test($input, $output)) {
        return FALSE;
      }
    }

    return TRUE;
  }

  /**
   * Tests if authentication is required to submit messages.
   *
   * @param \Symfony\Component\Console\Input\InputInterface $input
   *   The console input.
   * @param \Symfony\Component\Console\Output\OutputInterface $output
   *   The console output.
   *
   * @return bool
   *   TRUE if the test passed, FALSE otherwise.
   */
  protected function testAuthenticationIsRequiredForSubmission(InputInterface $input, OutputInterface $output) {
    $connection = $this->getConnection($input);

    $output->write('Testing if authentication is required to submit messages ... ');

    // Ensure that the server requires authentication to submit messages.
    if (!$connection->isAuthenticationRequired()) {
      $output->writeln('<error>FAIL</error>');
      return FALSE;
    }

    $output->writeln('<info>PASS</info>');
    return TRUE;
  }

  /**
   * Tests if one of CRAM-MD5, LOGIN, or PLAIN are supported.
   *
   * @param \Symfony\Component\Console\Input\InputInterface $input
   *   The console input.
   * @param \Symfony\Component\Console\Output\OutputInterface $output
   *   The console output.
   *
   * @return bool
   *   TRUE if the test passed, FALSE otherwise.
   */
  protected function testAuthenticationMechanismSupport(InputInterface $input, OutputInterface $output): bool {
    $connection = $this->getConnection($input);

    $output->write('Testing if one of CRAM-MD5, LOGIN, or PLAIN are supported ... ');

    // Ensure that the server has at least one of the supported SASL mechanisms.
    if (!\is_string($mechanism = \current(\array_intersect($connection->extensions['AUTH'], self::SUPPORTED_SASL_MECHANISMS)))) {
      $output->writeln('<error>FAIL</error>');
      return FALSE;
    }

    $output->writeln('<info>PASS</info>');
    return TRUE;
  }

  /**
   * Tests if the SMTP AUTH extension is supported.
   *
   * @param \Symfony\Component\Console\Input\InputInterface $input
   *   The console input.
   * @param \Symfony\Component\Console\Output\OutputInterface $output
   *   The console output.
   *
   * @return bool
   *   TRUE if the test passed, FALSE otherwise.
   */
  protected function testAuthenticationSupport(InputInterface $input, OutputInterface $output): bool {
    $connection = $this->getConnection($input);

    $output->write('Testing if the SMTP AUTH extension is supported ... ');

    // Ensure that the server supports the SMTP AUTH extension.
    if (!\array_key_exists('AUTH', $connection->extensions)) {
      $output->writeln('<error>FAIL</error>');
      return FALSE;
    }

    $output->writeln('<info>PASS</info>');
    return TRUE;
  }

  /**
   * Tests authentication requirements with invalid credentials.
   *
   * @param \Symfony\Component\Console\Input\InputInterface $input
   *   The console input.
   * @param \Symfony\Component\Console\Output\OutputInterface $output
   *   The console output.
   *
   * @return bool
   *   TRUE if the test passed, FALSE otherwise.
   */
  protected function testAuthenticationWithInvalidCredentials(InputInterface $input, OutputInterface $output): bool {
    $connection = $this->getConnection($input);

    $output->write('Testing if authentication fails with invalid credentials ... ');

    try {
      // Attempt to authenticate using invalid credentials.
      if ($mechanism = $this->getAuthenticationMechanism($connection->extensions['AUTH'], \bin2hex(\random_bytes(8)), \bin2hex(\random_bytes(8)))) {
        $connection->authenticate($mechanism);
      }

      // If we reach this point, the server accepted random credentials.
      $output->writeln('<error>FAIL</error>');
      return FALSE;
    }
    catch (AuthenticationException) {
      $output->writeln('<info>PASS</info>');
      return TRUE;
    }
  }

  /**
   * Tests authentication requirements with valid credentials.
   *
   * @param \Symfony\Component\Console\Input\InputInterface $input
   *   The console input.
   * @param \Symfony\Component\Console\Output\OutputInterface $output
   *   The console output.
   *
   * @return bool
   *   TRUE if the test passed, FALSE otherwise.
   */
  protected function testAuthenticationWithValidCredentials(InputInterface $input, OutputInterface $output): bool {
    $connection = $this->getConnection($input);

    $output->write('Testing if authentication succeeds with valid credentials ... ');

    try {
      // Attempt to authenticate using the supplied credentials.
      if ($mechanism = $this->getAuthenticationMechanism($connection->extensions['AUTH'], $input->getArgument('username'), $input->getArgument('password'))) {
        $connection->authenticate($mechanism);
        $output->writeln('<info>PASS</info>');
      }
    }
    catch (AuthenticationException) {
      // If we reach this point, the server did not accept our credentials.
      $output->writeln('<error>FAIL</error>');
      return FALSE;
    }

    $output->write('Testing if authentication is no longer required to submit messages ... ');

    // Ensure that the server no longer requires authentication.
    if ($connection->isAuthenticationRequired()) {
      $output->writeln('<error>FAIL</error>');
      return FALSE;
    }

    $output->writeln('<info>PASS</info>');
    return TRUE;
  }

  /**
   * Tests if TLSv1.2 or greater is being used.
   *
   * @param \Symfony\Component\Console\Input\InputInterface $input
   *   The console input.
   * @param \Symfony\Component\Console\Output\OutputInterface $output
   *   The console output.
   *
   * @return bool
   *   TRUE if the test passed, FALSE otherwise.
   */
  protected function testEncryptionProtocolVersion(InputInterface $input, OutputInterface $output): bool {
    $connection = $this->getConnection($input);

    $output->write('Testing if TLSv1.2 or greater is being used ... ');

    // Ensure that the server supports a modern encryption protocol.
    $protocol = $connection->getMetadata()['crypto']['protocol'] ?? NULL;
    if (!isset($protocol) || \in_array($protocol, ['TLSv1', 'TLSv1.1'])) {
      $output->writeln('<error>FAIL</error>');
      return FALSE;
    }

    $output->writeln('<info>PASS</info>');
    return TRUE;
  }

}
