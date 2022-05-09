<?php

declare(strict_types = 1);

namespace LibraryMarket\mstt\SMTP;

use LibraryMarket\mstt\SMTP\Exception\ConnectException;
use LibraryMarket\mstt\SMTP\Exception\GreetingException;
use LibraryMarket\mstt\SMTP\Exception\ReadException;

/**
 * Facilitates connecting to a message submission agent via (E)SMTP.
 */
class Connection {

  const DEFAULT_TIMEOUT = 3.0;

  /**
   * The IP address or hostname of the message submission agent.
   *
   * @var string
   */
  public readonly string $address;

  /**
   * The self-reported identity of the message submission agent.
   *
   * @var string
   */
  public readonly string $identity;

  /**
   * The port used by the message submission agent.
   *
   * @var int
   */
  public readonly int $port;

  /**
   * The socket used to communicate with the message submission agent.
   *
   * @var resource
   */
  protected $socket;

  /**
   * The stream context to use when opening a stream socket client.
   *
   * @var resource
   */
  protected $streamContext;

  /**
   * Constructs a Connection object.
   *
   * @param string $address
   *   The IP address or hostname of the message submission agent.
   * @param int $port
   *   The port used by the message submission agent.
   * @param \LibraryMarket\mstt\SMTP\ConnectionType $connection_type
   *   The type of connection to establish to the message submission agent.
   * @param resource|null $stream_context
   *   An optional stream context to use for the internal stream socket client.
   *
   * @throws \InvalidArgumentException
   *   If the supplied address is neither a valid IP address or hostname.
   *   Currently, only IPv4 and IPv6 addresses are supported.
   * @throws \DomainException
   *   If the supplied port is not a valid port number.
   */
  public function __construct(string $address, int $port = 587, ConnectionType $connection_type = ConnectionType::STARTTLS, $stream_context = NULL) {
    $flags = \FILTER_FLAG_IPV4 | \FILTER_FLAG_IPV6;

    // Check that a valid IP address or hostname was supplied.
    if (!\filter_var($address, \FILTER_VALIDATE_IP, $flags) && !\filter_var(\gethostbyname($address), \FILTER_VALIDATE_IP, $flags)) {
      throw new \InvalidArgumentException('The supplied SMTP server address is invalid: ' . $address);
    }

    // Check that a valid port was supplied.
    if ($port < 1 || $port > 65_535) {
      throw new \DomainException('The supplied SMTP port is invalid');
    }

    // Attempt to set the supplied stream context.
    if (isset($stream_context)) {
      $this->setStreamContext($stream_context);
    }

    $this->connectionType = $connection_type;
    $this->address = $address;
    $this->port = $port;
  }

  /**
   * Disconnect from any active connection on destruction.
   */
  public function __destruct() {
    $this->disconnect();
  }

  /**
   * Attempt to connect to the message submission agent.
   *
   * Calling this method will incur no read/write operations on the data stream.
   * TLS negotiation may occur if the TLS connection type was specified.
   *
   * @param float $connect_timeout
   *   The timeout period in seconds to use while attempting to establish a
   *   connection to the message submission agent (default: 3.0).
   * @param float $read_write_timeout
   *   The timeout period in seconds to use when reading from or writing to the
   *   underlying stream socket (default: 3.0).
   *
   * @throws \LibraryMarket\mstt\SMTP\Exception\ConnectException
   *   If the connection to the message submission agent failed.
   * @throws \LogicException
   *   If there is already an active connection.
   * @throws \RuntimeException
   *   If the socket could not be configured.
   */
  public function connect(float $connect_timeout = self::DEFAULT_TIMEOUT, float $read_write_timeout = self::DEFAULT_TIMEOUT): void {
    // Ensure that there isn't already an active connection.
    if (\is_resource($this->socket)) {
      throw new \LogicException('There is already an active connection');
    }

    // Attempt to open a stream socket client.
    if (!$socket = \stream_socket_client($this->getClientAddress(), context: $this->getStreamContext(), error_code: $error_code, error_message: $error_message, timeout: $connect_timeout)) {
      throw new ConnectException('Unable to connect to the message submission agent: ' . $error_message, $error_code);
    }

    // Attempt to configure the socket.
    if (!\stream_set_timeout($socket, \intval($read_write_timeout), \intval($read_write_timeout * 1E6))) {
      throw new \RuntimeException('Unable to configure the underlying stream socket');
    }

    $this->socket = $socket;
  }

  /**
   * Disconnect from the message submission agent.
   *
   * This message is safe to call even if there is no active connection.
   */
  public function disconnect(): void {
    if (\is_resource($this->socket)) {
      @\fclose($this->socket);
    }

    $this->socket = NULL;
  }

  /**
   * Get the stream context to use when opening a stream socket client.
   *
   * @see \stream_context_get_default()
   *   The default stream context is used for lazy initialization of the
   *   underlying stream context upon first invocation.
   *
   * @return resource
   *   The stream context to use when opening a stream socket client.
   */
  public function getStreamContext() {
    if (!isset($this->streamContext)) {
      $this->streamContext = \stream_context_get_default();
    }

    return $this->streamContext;
  }

  /**
   * Get the address string to use when calling stream_socket_client().
   *
   * @return string
   *   The address string to use when calling stream_socket_client().
   */
  public function getClientAddress(): string {
    $address = $this->address;
    if (\filter_var($this->address, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
      $address = "[{$this->address}]";
    }

    $endpoint = "tcp://{$address}:{$this->port}";
    if ($this->connectionType === ConnectionType::TLS) {
      $endpoint = "tls://{$address}:{$this->port}";
    }

    return $endpoint;
  }

  /**
   * Probe the message submission agent for its identity and extensions.
   *
   * @throws \GreetingException
   *   If the remote server initiated the connection with an invalid greeting,
   *   or if no greeting was sent by the remote server.
   */
  public function probe(): void {
    try {
      $greeting = $this->read(TRUE);
    }
    catch (ReadException $e) {
      $greeting = '';
    }

    // Ensure that the server sent a valid greeting before continuing.
    if (empty($greeting)) {
      throw new GreetingException('The remote server did not initiate the connection with a greeting');
    }
    if (!\preg_match('/^220 (?P<identity>\\S+).*/', $greeting, $matches)) {
      throw new GreetingException('The remote server initiated the connection with an invalid greeting');
    }

    // Store the message submission agent's self-reported identity.
    if (!isset($this->identity)) {
      $this->identity = $matches['identity'];
    }
  }

  /**
   * Attempt to read a line from the message submission agent.
   *
   * @throws \LibraryMarket\mstt\SMTP\Exception\ReadException
   *   If unable to read from the underlying stream socket.
   * @throws \RuntimeException
   *   If there is currently no active connection.
   *
   * @return string
   *   A message from the message submission agent.
   */
  protected function read(): string {
    if (!\is_resource($this->socket)) {
      throw new \RuntimeException('There is currently no active connection');
    }
    if (!\is_string($result = \fgets($this->socket))) {
      throw new ReadException('Unable to read from the underlying stream socket');
    }

    return \preg_replace('/\\r?\\n$/', '', $result);
  }

  /**
   * Set the stream context to use for new connections.
   *
   * A new connection must be established for the supplied context to be used.
   *
   * @param resource $context
   *   The stream context to use for new connections.
   *
   * @throws \InvalidArgumentException
   *   If the supplied argument is not a valid stream context resource.
   */
  public function setStreamContext($context): void {
    if (!\is_resource($context) || \get_resource_type($context) !== 'stream-context') {
      throw new \InvalidArgumentException('The supplied argument is not a valid stream context resource');
    }

    $this->streamContext = $context;
  }

}
