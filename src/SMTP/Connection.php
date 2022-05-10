<?php

declare(strict_types = 1);

namespace LibraryMarket\mstt\SMTP;

use LibraryMarket\mstt\SMTP\Exception\ClientGreetingException;
use LibraryMarket\mstt\SMTP\Exception\ConnectException;
use LibraryMarket\mstt\SMTP\Exception\CryptoException;
use LibraryMarket\mstt\SMTP\Exception\ReadException;
use LibraryMarket\mstt\SMTP\Exception\ServerGreetingException;
use LibraryMarket\mstt\SMTP\Exception\WriteException;

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
   * The type of connection.
   *
   * @var \LibraryMarket\mstt\SMTP\ConnectionType
   */
  public readonly ConnectionType $connectionType;

  /**
   * An associative array representing the extensions supported by the server.
   *
   * The array keys consist of extension keywords (normalized), while the array
   * values consist of a list of unprocessed extension parameters.
   *
   * When the STARTTLS connection type is used, the extensions in this array
   * represent the available extensions after crypto has been enabled.
   *
   * This property is not initialized until the message submission agent has
   * been probed for its supported extensions.
   *
   * @see ::probe()
   *   Invoke this method to initialize this property.
   *
   * @var array
   *
   * @phpstan-ignore-next-line
   */
  public readonly array $extensions;

  /**
   * The self-reported identity of the message submission agent.
   *
   * This property is not initialized until the message submission agent has
   * been probed for its self-reported identity.
   *
   * @see ::probe()
   *   Invoke this method to initialize this property.
   *
   * @var string
   *
   * @phpstan-ignore-next-line
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
   * @var resource|null
   */
  protected $socket;

  /**
   * The stream context to use when opening a stream socket client.
   *
   * @var resource|null
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
   *   The stream context to use for new connections.
   *
   * @throws \InvalidArgumentException
   *   If the supplied argument is not a valid stream context resource.
   * @throws \DomainException
   *   If the supplied port is not a valid port number.
   * @throws \UnexpectedValueException
   *   If the supplied address is neither a valid IP address or hostname.
   *   Currently, only IPv4 and IPv6 addresses are supported.
   */
  public function __construct(string $address, int $port = 587, ConnectionType $connection_type = ConnectionType::STARTTLS, $stream_context = NULL) {
    $flags = \FILTER_FLAG_IPV4 | \FILTER_FLAG_IPV6;

    // Check that a valid IP address or hostname was supplied.
    if (!\filter_var($address, \FILTER_VALIDATE_IP, $flags) && !\filter_var(\gethostbyname($address), \FILTER_VALIDATE_IP, $flags)) {
      throw new \UnexpectedValueException('The supplied SMTP server address is invalid: ' . $address);
    }

    // Check that a valid port was supplied.
    if ($port < 1 || $port > 65_535) {
      throw new \DomainException('The supplied SMTP port is invalid');
    }

    // Use the supplied stream context (if available).
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
   * At the time of writing, there isn't a clean way to retrieve OpenSSL errors.
   * For now, a custom error handler is used during the execution of this method
   * as a workaround to intercept any errors that occur when calling
   * \stream_socket_client().
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

    // Set a custom error handler to intercept any errors that occur when
    // calling \stream_socket_client().
    \set_error_handler(function (int $errno, string $errstr) {
      throw new ConnectException('Unable to connect to the message submission agent: ' . $errstr, $errno);
    });

    try {
      $error_code = 0;
      $error_message = '';

      // Attempt to open a stream socket client.
      if (!$socket = @\stream_socket_client($this->getClientAddress(), context: $this->getStreamContext(), error_code: $error_code, error_message: $error_message, timeout: $connect_timeout)) {
        throw new ConnectException('Unable to connect to the message submission agent: ' . $error_message, $error_code);
      }
    }
    finally {
      \restore_error_handler();
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
   * Get the address string to use when calling \stream_socket_client().
   *
   * @return string
   *   The address string to use when calling \stream_socket_client().
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
   * Attempt to read a command response from the remote server.
   *
   * @throws \LibraryMarket\mstt\SMTP\Exception\ReadException
   *   If unable to read from the underlying stream socket.
   * @throws \RuntimeException
   *   If there is currently no active connection.
   *
   * @return object
   *   A first class object with the following properties:
   *   - code: the reply code for the response (int|null).
   *   - lines: an array of strings that represent the lines of the response.
   */
  protected function getResponse(): object {
    $result = (object) [
      'code' => NULL,
      'lines' => [],
    ];

    // Define an anonymous function used to parse reply lines from the server.
    $parse = function ($response) {
      $expr = '/^(?P<code>[2-5][0-5][0-9])(?P<type>[- ])(?P<textstring>.*)$/';

      if (\preg_match($expr, $response, $matches)) {
        return \array_filter($matches, \is_string(...), \ARRAY_FILTER_USE_KEY);
      }

      return [];
    };

    do {
      // Attempt to parse a reply line from the underlying stream socket.
      if ($response = $parse($this->read())) {
        $result->code ??= \intval($response['code']);
        $result->lines[] = $response['textstring'];
      }

      // Continue reading while the server indicates there are remaining lines.
    } while (($response['type'] ?? NULL) === '-');

    return $result;
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
   * Probe the message submission agent for its identity and extensions.
   *
   * When using the STARTTLS connection type, extension negotiation will occur
   * twice to ensure that crypto-exclusive extensions can be probed.
   *
   * Crypto-related exceptions are only thrown when using STARTTLS.
   *
   * @throws \LibraryMarket\mstt\SMTP\Exception\ClientGreetingException
   *   If the remote server did not send a valid response to the client
   *   greeting, or if the client greeting resulted in a bad response.
   * @throws \LibraryMarket\mstt\SMTP\Exception\CryptoException
   *   If crypto could not be enabled on the underlying stream socket.
   * @throws \LibraryMarket\mstt\SMTP\Exception\ServerGreetingException
   *   If the remote server did not initiate the connection with a greeting, or
   *   if the remote server initiated the connection with an invalid greeting.
   * @throws \LibraryMarket\mstt\SMTP\Exception\WriteException
   *   If unable to write to the underlying stream socket.
   * @throws \RuntimeException
   *   If there is currently no active connection.
   */
  public function probe(): void {
    $extensions = [];

    // Attempt to process the initial greeting sent by the server on connection.
    $this->processServerGreeting();

    try {
      // Attempt to send an Extended Hello client greeting and process the
      // server's response which enumerates all supported extensions.
      $this->sendClientGreeting(ClientGreetingType::Extended);
      $extensions = $this->processClientGreetingResponse();
    }
    catch (ClientGreetingException $e) {
      // Fall back to the basic Hello client greeting on failure.
      $this->sendClientGreeting(ClientGreetingType::Basic);
      $extensions = $this->processClientGreetingResponse();
    }

    // Check if the STARTTLS connection type was requested.
    if ($this->connectionType === ConnectionType::STARTTLS) {
      // Ensure that the remote server supports the STARTTLS extension.
      if (!\array_key_exists('STARTTLS', $extensions)) {
        throw new CryptoException('The remote server does not support the STARTTLS extension to SMTP');
      }

      // Attempt to enable crypto on the underlying stream socket.
      $this->streamEnableCrypto();

      // Renegotiate extension support after enabling crypto.
      $this->sendClientGreeting(ClientGreetingType::Extended);
      $extensions = $this->processClientGreetingResponse();
    }

    // Store the remote server's supported extensions.
    // @phpstan-ignore-next-line
    $this->extensions ??= $extensions;
  }

  /**
   * Attempt to process the remote server's response to the client greeting.
   *
   * @throws \LibraryMarket\mstt\SMTP\Exception\ClientGreetingException
   *   If the remote server did not send a valid response to the client
   *   greeting, or if the client greeting resulted in a bad response.
   * @throws \RuntimeException
   *   If there is currently no active connection.
   *
   * @return array
   *   An associative array of extensions supported by the remote server.
   *
   * @phpstan-ignore-next-line
   */
  protected function processClientGreetingResponse(): array {
    $extensions = [];

    try {
      $response = $this->getResponse();
    }
    catch (ReadException $e) {
    }

    if (!isset($response) || !isset($response->code)) {
      throw new ClientGreetingException('The remote server did not send a valid response to the client greeting');
    }
    if ($response->code !== 250) {
      throw new ClientGreetingException('The client greeting resulted in a bad response from the remote server: ' . \implode("\r\n", $response->lines ?? []), $response->code);
    }

    if (isset($response->lines) && is_array($response->lines)) {
      // Discard the first line of the response and reset the extension list.
      \array_shift($response->lines);

      // Build an associative array of extensions supported by the server.
      foreach ($response->lines as $line) {
        if ($extension = \preg_split('/\\s+/', $line)) {
          $extensions[\strtoupper(\array_shift($extension))] = $extension;
        }
      }
    }

    return $extensions;
  }

  /**
   * Attempt to process the initial greeting sent by the server on connection.
   *
   * The remote server's self-reported identity will be updated upon the first
   * successful invocation of this method.
   *
   * @throws \LibraryMarket\mstt\SMTP\Exception\ServerGreetingException
   *   If the remote server did not initiate the connection with a greeting, or
   *   if the remote server initiated the connection with an invalid greeting.
   * @throws \RuntimeException
   *   If there is currently no active connection.
   */
  protected function processServerGreeting(): void {
    try {
      $greeting = $this->getResponse();
    }
    catch (ReadException $e) {
    }

    // Ensure that the server sent a valid greeting before continuing.
    if (!isset($greeting) || !isset($greeting->code)) {
      throw new ServerGreetingException('The remote server did not initiate the connection with a valid greeting');
    }
    if ($greeting->code !== 220) {
      throw new ServerGreetingException('The remote server initiated the connection with a bad greeting: ' . \implode("\r\n", $greeting->lines ?? []), $greeting->code);
    }

    if (isset($greeting->lines) && is_array($greeting->lines)) {
      // Store the remote server's self-reported identity.
      // @phpstan-ignore-next-line
      $this->identity ??= \preg_replace('/\\s.*/', '', \array_shift($greeting->lines) ?? '');
    }
  }

  /**
   * Attempt to read a line from the remote server.
   *
   * @throws \LibraryMarket\mstt\SMTP\Exception\ReadException
   *   If unable to read from the underlying stream socket.
   * @throws \RuntimeException
   *   If there is currently no active connection.
   *
   * @return string
   *   A message from the remote server.
   */
  protected function read(): string {
    if (!\is_resource($this->socket)) {
      throw new \RuntimeException('There is currently no active connection');
    }
    if (!\is_string($result = \fgets($this->socket))) {
      throw new ReadException('Unable to read from the underlying stream socket');
    }

    return \preg_replace('/\\r?\\n$/', '', $result) ?? '';
  }

  /**
   * Attempt to send the client greeting to the remote server.
   *
   * @param \LibraryMarket\mstt\SMTP\ClientGreetingType $type
   *   The type of client greeting to send to the remote server.
   *
   * @throws \LibraryMarket\mstt\SMTP\Exception\WriteException
   *   If unable to write to the underlying stream socket.
   * @throws \RuntimeException
   *   If there is currently no active connection.
   */
  protected function sendClientGreeting(ClientGreetingType $type): void {
    $this->write("{$type->value} librarymarket.com");
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

  /**
   * Perform crypto negotiation with the remote server using STARTTLS.
   *
   * At the time of writing, there isn't a clean way to retrieve OpenSSL errors
   * that occur when attempting to enable crypto on a stream socket. For now, a
   * custom error handler is used during the execution of this method as a
   * workaround to intercept any errors that occur when calling
   * \stream_socket_enable_crypto().
   *
   * @throws \LibraryMarket\mstt\SMTP\Exception\CryptoException
   *   If crypto could not be enabled on the underlying stream socket.
   * @throws \RuntimeException
   *   If there is currently no active connection.
   */
  protected function streamEnableCrypto(): void {
    try {
      // Inform the remote server that we want to perform crypto negotiation.
      $this->write('STARTTLS');

      // Attempt to read a response from the remote server to determine if
      // crypto negotiation can begin or if an error occurred.
      $response = $this->getResponse();
    }
    catch (ReadException | WriteException $e) {
    }

    // Check if the server did not respond to our request to start crypto.
    if (!isset($response) || !isset($response->code)) {
      throw new CryptoException('Unable to enable STARTTLS on the underlying stream socket: the server did not reply to the STARTTLS command');
    }

    // Check if the server responded with a bad reply code.
    if ($response->code !== 220) {
      throw new CryptoException('Unable to enable STARTTLS on the underlying stream socket: ' . \implode("\r\n", $response->lines ?? []), $response->code);
    }

    // Ensure that there is an active connection before continuing.
    if (!\is_resource($this->socket)) {
      throw new \RuntimeException('There is currently no active connection');
    }

    // Set a custom error handler to intercept any errors that occur when
    // calling \stream_socket_enable_crypto().
    \set_error_handler(function (int $errno, string $errstr) {
      throw new CryptoException('Unable to enable STARTTLS on the underlying stream socket: ' . $errstr, $errno);
    });

    try {
      // Attempt to enable crypto on the underlying stream socket.
      //
      // If our custom error handler is not encountered, we should still check
      // for a FALSE return value and throw a generic exception if crypto could
      // not be enabled for the stream socket.
      if (!@\stream_socket_enable_crypto($this->socket, TRUE, \STREAM_CRYPTO_METHOD_ANY_CLIENT)) {
        throw new CryptoException('Unable to enable STARTTLS on the underlying stream socket');
      }
    }
    finally {
      \restore_error_handler();
    }
  }

  /**
   * Attempt to send a line to the remote server.
   *
   * @param string $line
   *   The line to send (excluding line endings).
   *
   * @throws \LibraryMarket\mstt\SMTP\Exception\WriteException
   *   If unable to write to the underlying stream socket.
   * @throws \RuntimeException
   *   If there is currently no active connection.
   */
  protected function write(string $line): void {
    if (!\is_resource($this->socket)) {
      throw new \RuntimeException('There is currently no active connection');
    }
    if (!\fwrite($this->socket, "{$line}\r\n")) {
      throw new WriteException('Unable to write to the underlying stream socket');
    }
  }

}
