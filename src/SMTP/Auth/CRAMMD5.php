<?php

declare(strict_types = 1);

namespace LibraryMarket\mstt\SMTP\Auth;

use LibraryMarket\mstt\SMTP\AuthenticationBase;

/**
 * The 'CRAM-MD5' SASL authentication mechanism.
 */
class CRAMMD5 extends AuthenticationBase {

  /**
   * Whether a challenge from the remote server has been processed.
   *
   * @var bool
   */
  protected bool $processed = FALSE;

  /**
   * Constructs a CRAMMD5 object.
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
    return 'CRAM-MD5';
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
      // Compute the challenge response reply to send to the remote server.
      return \base64_encode($this->username . ' ' . \hash_hmac('md5', \base64_decode(\reset($response)), $this->password));
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
