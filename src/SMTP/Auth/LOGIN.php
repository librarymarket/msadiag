<?php

declare(strict_types = 1);

namespace LibraryMarket\mstt\SMTP\Auth;

use LibraryMarket\mstt\SMTP\AuthenticationBase;

/**
 * The 'LOGIN' SASL authentication mechanism.
 */
class LOGIN extends AuthenticationBase {

  /**
   * Whether the password has been sent.
   *
   * @var bool
   */
  protected bool $sentPassword = FALSE;

  /**
   * Whether the username has been sent.
   *
   * @var bool
   */
  protected bool $sentUsername = FALSE;

  /**
   * Constructs a LOGIN object.
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
    return 'LOGIN';
  }

  /**
   * {@inheritdoc}
   */
  public function process(array $response): string {
    // Check if the username challenge was sent by the remote server.
    if (\reset($response) === 'VXNlcm5hbWU6') {
      if ($this->sentUsername) {
        throw new \LogicException('The username was requested multiple times by the remote server; authentication can only be attempted once');
      }

      try {
        return \base64_encode($this->username);
      }
      finally {
        $this->sentUsername = TRUE;
      }
    }
    // Check if the password challenge was sent by the remote server.
    elseif (\reset($response) === 'UGFzc3dvcmQ6') {
      if ($this->sentPassword) {
        throw new \LogicException('The password was requested multiple times by the remote server; authentication can only be attempted once');
      }

      try {
        return \base64_encode($this->password);
      }
      finally {
        $this->sentPassword = TRUE;
      }
    }
    else {
      throw new \LogicException('An unknown LOGIN challenge was sent by the remote server: ' . \reset($response));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function reset(): void {
    $this->sentPassword = FALSE;
    $this->sentUsername = FALSE;
  }

}
