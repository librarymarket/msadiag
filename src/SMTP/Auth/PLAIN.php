<?php

declare(strict_types = 1);

namespace LibraryMarket\mstt\SMTP\Auth;

use LibraryMarket\mstt\SMTP\AuthenticationBase;

/**
 * The 'PLAIN' SASL authentication mechanism.
 */
class PLAIN extends AuthenticationBase {

  /**
   * Whether a challenge from the remote server has been processed.
   *
   * @var bool
   */
  protected bool $processed = FALSE;

  /**
   * Constructs a PLAIN object.
   *
   * @param string $username
   *   The username to use for authentication.
   * @param string $password
   *   The password to use for authentication.
   */
  public function __construct(protected string $username, protected string $password) {
  }

  /**
   * {@inheritdoc}
   */
  public function name(): string {
    return 'PLAIN';
  }

  /**
   * {@inheritdoc}
   *
   * @throws \LogicException
   *   If the remote server requests multiple responses.
   */
  public function process(array $response): string {
    // Ensure that this method is only invoked once.
    if ($this->processed) {
      throw new \LogicException('Multiple responses are not supported by this authentication mechanism');
    }

    try {
      // Send the credentials to the remote server.
      return \base64_encode("{$this->username}\0{$this->username}\0{$this->password}");
    }
    finally {
      // Mark the challenge as having been processed.
      $this->processed = TRUE;
    }
  }

  /**
   * {@inheritdoc}
   */
  public function reset(): void {
    $this->processed = FALSE;
  }

}
