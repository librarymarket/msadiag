<?php

declare(strict_types = 1);

namespace LibraryMarket\msadiag\Command;

use LibraryMarket\msadiag\Exception\TestFailureException;
use LibraryMarket\msadiag\SMTP\ConnectionFactory;
use LibraryMarket\msadiag\SMTP\ConnectionFactoryInterface;
use LibraryMarket\msadiag\ValidationTests;

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

  /**
   * The SMTP connection factory.
   *
   * @var \LibraryMarket\msadiag\SMTP\ConnectionFactoryInterface
   */
  public ConnectionFactoryInterface $connectionFactory;

  /**
   * {@inheritdoc}
   */
  public function __construct(string $name = NULL, ?ConnectionFactoryInterface $connection_factory = NULL) {
    $this->connectionFactory = $connection_factory ??= new ConnectionFactory();

    parent::__construct($name);
  }

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
      ' * The server must not require authentication to submit messages after successful authentication.',
    ]));

    $this->addArgument('server-address', InputArgument::REQUIRED, 'The address of the SMTP server');
    $this->addArgument('server-port', InputArgument::REQUIRED, 'The port of the SMTP server');
    $this->addArgument('username', InputArgument::REQUIRED, 'The username to use for authentication');
    $this->addArgument('password', InputArgument::REQUIRED, 'The password to use for authentication');

    $this->addOption('sender', NULL, InputOption::VALUE_REQUIRED, 'The sender address to use for checking authentication', '');
    $this->addOption('strict', NULL, InputOption::VALUE_NONE, 'Run strict tests in addition to all other tests');
    $this->addOption('tls', NULL, InputOption::VALUE_NONE, 'Use TLS for encryption instead of STARTTLS');
  }

  /**
   * Print a debug log resulting from a test failure.
   *
   * @param string $message
   *   The message to display.
   */
  protected function debug(string $message): void {
    if ($message = \preg_split('/\\r?\\n/', $message)) {
      $this->io->getErrorStyle()->section('Debug Log');

      foreach ($message as $line) {
        $this->io->getErrorStyle()->writeln("  {$line}");
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  protected function execute(InputInterface $input, OutputInterface $output): int {
    $this->io = new SymfonyStyle($input, $output);
    $this->output = $output;

    $validation = new ValidationTests(
      $input->getArgument('server-address'),
      \intval($input->getArgument('server-port')),
      $input->getOption('tls'),
      $input->getArgument('username'),
      $input->getArgument('password'),
      $input->getOption('strict'),
      $input->getOption('sender'),
      $this->connectionFactory
    );

    if (!$this->runTests($validation)) {
      return 1;
    }

    $this->output->writeln('');
    $this->output->writeln('<info>The server passed all tests.</info>');

    return 0;
  }

  /**
   * Run a sequence of tests and return the aggregate result.
   *
   * @param \LibraryMarket\msadiag\ValidationTests $validation
   *   The object representing the validation tests to run.
   *
   * @return bool
   *   TRUE if none of the tests failed, FALSE otherwise.
   */
  protected function runTests(ValidationTests $validation): bool {
    $results = TRUE;

    foreach ($validation->getTests() as $description => $test) {
      if (!\is_callable($test) || !$this->runTest(\strval($description), $test)) {
        $results = FALSE;
      }
    }

    return $results;
  }

  /**
   * Run a specific test case and return the result.
   *
   * @param string $description
   *   A description of the validation test method.
   * @param callable $test
   *   The test case to run.
   *
   * @return bool
   *   TRUE if the test passes, FALSE otherwise.
   */
  protected function runTest(string $description, callable $test): bool {
    $result = TRUE;

    try {
      $this->output->write("{$description} ... ");
      $test();
      $this->output->writeln('<info>PASS</info>');
    }
    catch (TestFailureException $e) {
      $result = FALSE;
      $this->output->writeln('<error>FAIL</error>');
      $this->debug($e->getMessage());
    }

    return $result;
  }

}
