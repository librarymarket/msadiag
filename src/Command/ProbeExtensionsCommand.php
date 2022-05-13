<?php

declare(strict_types = 1);

namespace LibraryMarket\msadiag\Command;

use Composer\CaBundle\CaBundle;

use LibraryMarket\msadiag\SMTP\Connection;
use LibraryMarket\msadiag\SMTP\ConnectionType;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Helper\TableSeparator;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Probe the specified SMTP server for its supported extensions.
 */
class ProbeExtensionsCommand extends Command {

  /**
   * {@inheritdoc}
   */
  protected function configure(): void {
    $this->setName('probe:extensions');
    $this->setAliases(['ext', 'extensions', 'pr-ext', 'pr:ext']);
    $this->setDescription('Probe the specified SMTP server for its supported extensions');
    $this->setHelp('This command connects to the specified SMTP server and probes it for its supported extensions.');

    $this->addArgument('server-address', InputArgument::REQUIRED, 'The address of the SMTP server');
    $this->addArgument('server-port', InputArgument::REQUIRED, 'The port of the SMTP server');

    $this->addOption('encryption-type', NULL, InputOption::VALUE_REQUIRED, 'The type of connection to initiate (auto, none, plain, STARTTLS, or TLS)', 'auto');
    $this->addOption('format', NULL, InputOption::VALUE_REQUIRED, 'The output format of this command (console, CSV, or JSON)', 'console');
  }

  /**
   * {@inheritdoc}
   */
  protected function execute(InputInterface $input, OutputInterface $output): int {
    try {
      $format = \strtoupper($input->getOption('format'));
      $format = match ($format) {
        'CONSOLE' => $this->printServerExtensionsConsole(...),
        'CSV' => $this->printServerExtensionsCommaSeparatedValue(...),
        'JSON' => fn ($output, $ext) => $output->writeln(\json_encode($ext)),
      };
    }
    catch (\UnhandledMatchError $e) {
      throw new \InvalidArgumentException('The supplied format is invalid: ' . $input->getOption('format'));
    }

    try {
      $connection_type = \strtoupper($input->getOption('encryption-type'));
      $connection_type = match ($connection_type) {
        'AUTO' => ConnectionType::Auto,
        'NONE' => ConnectionType::PlainText,
        'PLAIN' => ConnectionType::PlainText,
        'STARTTLS' => ConnectionType::STARTTLS,
        'TLS' => ConnectionType::TLS,
      };
    }
    catch (\UnhandledMatchError $e) {
      throw new \InvalidArgumentException('The supplied encryption type is invalid: ' . $input->getOption('encryption-type'));
    }

    $address = $input->getArgument('server-address');
    $port = \intval($input->getArgument('server-port'));

    $connection = new Connection($address, $port, $connection_type);
    $connection->setStreamContext(\stream_context_get_default([
      'ssl' => [
        'SNI_enabled' => TRUE,
        'allow_self_signed' => FALSE,
        'cafile' => CaBundle::getBundledCaBundlePath(),
        'capath' => \dirname(CaBundle::getBundledCaBundlePath()),
        'crypto_method' => \STREAM_CRYPTO_METHOD_ANY_CLIENT,
        'disable_compression' => TRUE,
        'verify_peer' => TRUE,
        'verify_peer_name' => TRUE,
      ],
    ]));

    $connection->connect();
    $connection->probe();

    $extensions = $connection->extensions;

    \ksort($extensions);
    \uasort($extensions, fn ($a, $b) => \count($b) <=> \count($a));

    $format($output, $extensions);

    return Command::SUCCESS;
  }

  /**
   * Print the extensions supported by the remote server in a table.
   *
   * @param \Symfony\Component\Console\Output\OutputInterface $output
   *   The output interface to which the table should be rendered.
   * @param array $extensions
   *   An associative array of extensions supported by the remote server.
   *
   * @phpstan-ignore-next-line
   */
  protected function printServerExtensionsConsole(OutputInterface $output, array $extensions): void {
    if (empty($extensions)) {
      $output->writeln('The remote server did not advertise any extensions.');
      return;
    }

    $table = new Table($output);

    $table->setHeaderTitle('Extensions');
    $table->setHeaders(['Name', 'Parameter List']);

    $rows = [];
    foreach ($extensions as $extension => $parameters) {
      $rows[] = [$extension, \implode("\n", $parameters)];
      $rows[] = new TableSeparator();
    }

    // Remove any trailing table separators from the end of the table.
    if (\end($rows) instanceof TableSeparator) {
      \array_pop($rows);
    }

    $table->setRows($rows);
    $table->render();
  }

  /**
   * Print the extensions supported by the remote server in CSV format.
   *
   * @param \Symfony\Component\Console\Output\OutputInterface $output
   *   The output interface to which the CSV should be rendered.
   * @param array $extensions
   *   An associative array of extensions supported by the remote server.
   *
   * @phpstan-ignore-next-line
   */
  protected function printServerExtensionsCommaSeparatedValue(OutputInterface $output, array $extensions): void {
    if (empty($extensions)) {
      return;
    }

    if (!$fh = \fopen('php://memory', 'r+')) {
      throw new \RuntimeException('Unable to create temporary buffer to generate CSV output');
    }

    \fputcsv($fh, ['Name', 'Parameter List']);
    foreach ($extensions as $extension => $parameters) {
      \fputcsv($fh, [$extension, \implode(' ', $parameters)]);
    }

    \rewind($fh);

    // Write the contents of the buffer to the supplied output.
    if ($result = \stream_get_contents($fh)) {
      $output->write($result);
    }

    \fclose($fh);
  }

}
