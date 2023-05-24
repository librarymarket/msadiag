<?php

declare(strict_types = 1);

namespace LibraryMarket\msadiag\Command;

use Composer\CaBundle\CaBundle;

use LibraryMarket\msadiag\SMTP\ConnectionFactory;
use LibraryMarket\msadiag\SMTP\ConnectionFactoryInterface;
use LibraryMarket\msadiag\SMTP\ConnectionType;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Probe the specified SMTP server for encryption information.
 */
class ProbeEncryptionCommand extends Command {

  /**
   * The SMTP connection factory.
   *
   * @var \LibraryMarket\msadiag\SMTP\ConnectionFactoryInterface
   */
  public ConnectionFactoryInterface $connectionFactory;

  /**
   * {@inheritdoc}
   */
  public function __construct(string $name = NULL) {
    $this->connectionFactory = new ConnectionFactory();
    parent::__construct($name);
  }

  /**
   * {@inheritdoc}
   */
  protected function configure(): void {
    $this->setName('probe:encryption');
    $this->setAliases(['crypto', 'encryption', 'pr-enc', 'pr:enc']);
    $this->setDescription('Probe the specified SMTP server for encryption information');
    $this->setHelp('This command connects to the specified SMTP server and probes it for information about its encryption support.');

    $this->addArgument('server-address', InputArgument::REQUIRED, 'The address of the SMTP server');
    $this->addArgument('server-port', InputArgument::REQUIRED, 'The port of the SMTP server');

    $this->addOption('tls', NULL, InputOption::VALUE_NONE, 'Use TLS for encryption instead of STARTTLS');
    $this->addOption('format', NULL, InputOption::VALUE_REQUIRED, 'The output format of this command (console, CSV, or JSON)', 'console');
  }

  /**
   * {@inheritdoc}
   */
  protected function execute(InputInterface $input, OutputInterface $output): int {
    try {
      $format = \strtoupper($input->getOption('format'));
      $format = match ($format) {
        'CONSOLE' => $this->printServerEncryptionConsole(...),
        'CSV' => $this->printServerEncryptionCommaSeparatedValue(...),
        'JSON' => fn ($output, $ext) => $output->writeln(\json_encode($ext)),
      };
    }
    catch (\UnhandledMatchError $e) {
      throw new \InvalidArgumentException('The supplied format is invalid: ' . $input->getOption('format'));
    }

    $connection_type = ConnectionType::STARTTLS;
    if ($input->getOption('tls')) {
      $connection_type = ConnectionType::TLS;
    }

    $address = $input->getArgument('server-address');
    $port = \intval($input->getArgument('server-port'));

    $connection = $this->connectionFactory->create($address, $port, $connection_type, \stream_context_get_default([
      'ssl' => [
        'SNI_enabled' => TRUE,
        'allow_self_signed' => TRUE,
        'cafile' => CaBundle::getBundledCaBundlePath(),
        'capath' => \dirname(CaBundle::getBundledCaBundlePath()),
        'crypto_method' => \STREAM_CRYPTO_METHOD_ANY_CLIENT,
        'disable_compression' => TRUE,
        'verify_peer' => FALSE,
        'verify_peer_name' => FALSE,
      ],
    ]));

    $connection->connect();
    $connection->probe();

    $default = [
      'protocol' => 'Unknown',
      'cipher_name' => 'Unknown',
      'cipher_bits' => 'Unknown',
      'cipher_version' => 'Unknown',
    ];

    $crypto = $connection->getMetadata()['crypto'] ?? [];
    $crypto = \array_replace($default, \array_intersect_key($crypto, $default));

    $format($output, $crypto);

    return 0;
  }

  /**
   * Print information about the remote server's encryption in a table.
   *
   * @param \Symfony\Component\Console\Output\OutputInterface $output
   *   The output interface to which the table should be rendered.
   * @param array $crypto
   *   An associative array of cryptographic information.
   *
   * @phpstan-ignore-next-line
   */
  protected function printServerEncryptionConsole(OutputInterface $output, array $crypto): void {
    $table = new Table($output);

    $table->setHeaderTitle('Encryption');
    $table->setHeaders(['Field', 'Value']);

    foreach ($crypto as $field => $value) {
      $table->addRow([$field, $value]);
    }

    $table->render();
  }

  /**
   * Print information about the remote server's encryption in CSV format.
   *
   * @param \Symfony\Component\Console\Output\OutputInterface $output
   *   The output interface to which the CSV should be rendered.
   * @param array $crypto
   *   An associative array of cryptographic information.
   *
   * @phpstan-ignore-next-line
   */
  protected function printServerEncryptionCommaSeparatedValue(OutputInterface $output, array $crypto): void {
    if (!$fh = \fopen('php://memory', 'r+')) {
      throw new \RuntimeException('Unable to create temporary buffer to generate CSV output');
    }

    \fputcsv($fh, ['Field', 'Value']);
    foreach ($crypto as $field => $value) {
      \fputcsv($fh, [$field, $value]);
    }

    \rewind($fh);

    // Write the contents of the buffer to the supplied output.
    if ($result = \stream_get_contents($fh)) {
      $output->write($result);
    }

    \fclose($fh);
  }

}
