<?php

declare(strict_types = 1);

namespace LibraryMarket\msadiag\SMTP;

/**
 * A generic SMTP connection factory.
 */
class ConnectionFactory implements ConnectionFactoryInterface {

  /**
   * {@inheritdoc}
   */
  public function create(string $address, int $port = 587, ConnectionType $connection_type = ConnectionType::STARTTLS, $stream_context = NULL): Connection {
    return new Connection($address, $port, $connection_type, $stream_context);
  }

}
