<?php

namespace LibraryMarket\mstt\Command;

use LibraryMarket\mstt\SMTP\Connection;
use LibraryMarket\mstt\SMTP\ConnectionType;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * A command to probe the specified SMTP server for encryption information.
 */
class ProbeEncryptionCommand extends Command {

  /**
   * {@inheritdoc}
   */
  protected function configure(): void {
    $this->setName('probe:encryption');
    $this->setAliases(['crypto', 'encryption', 'pr-enc', 'pr:enc']);
    $this->setDescription('Probe the specified SMTP server for encryption information');
    $this->setHelp('This command connects to the specified SMTP server and probes it for information about its encryption support.');

    $this->addArgument('server-address', InputArgument::REQUIRED, 'The address of the SMTP server');
    $this->addArgument('server-port', InputArgument::OPTIONAL, 'The port of the SMTP server', '25');

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

    $connection = new Connection($input->getArgument('server-address'), $input->getArgument('server-port'), $connection_type);

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

    return Command::SUCCESS;
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
    $output->write(\stream_get_contents($fh));

    \fclose($fh);
  }

}
