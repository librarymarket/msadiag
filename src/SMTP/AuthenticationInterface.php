<?php

declare(strict_types = 1);

namespace LibraryMarket\mstt\SMTP;

/**
 * Describes a SASL authentication mechanism.
 */
interface AuthenticationInterface {

  /**
   * Get the name of this authentication mechanism.
   *
   * @return string
   *   The name of this authentication mechanism.
   */
  public function name(): string;

  /**
   * Process a response from the remote server for authentication purposes.
   *
   * This method is responsible for driving the authentication process with the
   * remote server. This method may be called multiple successive times (e.g.,
   * in the case of a challenge-response flow).
   *
   * Internal state may need to be kept between successive calls.
   *
   * @param string[] $response
   *   The response lines from the remote server.
   *
   * @see ::reset()
   *   This method will be called when the authentication flow terminates to
   *   allow the mechanism to reset its internal state (if any).
   *
   * @return string
   *   A reply to send to the remote server after processing.
   */
  public function process(array $response): string;

  /**
   * Reset the internal state of this authentication mechanism (if any).
   */
  public function reset(): void;

}
