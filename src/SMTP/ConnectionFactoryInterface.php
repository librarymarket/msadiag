<?php

declare(strict_types = 1);

namespace LibraryMarket\msadiag\SMTP;

/**
 * Provides a connection factory interface for new SMTP connections.
 */
interface ConnectionFactoryInterface {

  /**
   * Get a new connection to the remote server.
   *
   * @param string $address
   *   The IP address or hostname of the message submission agent.
   * @param int $port
   *   The port used by the message submission agent.
   * @param \LibraryMarket\msadiag\SMTP\ConnectionType $connection_type
   *   The type of connection to establish to the message submission agent.
   * @param resource|null $stream_context
   *   The stream context to use for new connections.
   *
   * @return \LibraryMarket\msadiag\SMTP\Connection
   *   A connection to the remote server.
   */
  public function create(string $address, int $port = 587, ConnectionType $connection_type = ConnectionType::STARTTLS, $stream_context = NULL): Connection;

}
