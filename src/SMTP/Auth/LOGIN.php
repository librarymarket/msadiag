<?php

declare(strict_types = 1);

namespace LibraryMarket\msadiag\SMTP\Auth;

use LibraryMarket\msadiag\SMTP\AuthenticationBase;

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
   * Get the password challenge response.
   *
   * @throws \LogicException
   *   If the password challenge response is requested more than once.
   *
   * @return string
   *   The password challenge response.
   */
  protected function getPasswordChallengeResponse(): string {
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

  /**
   * Get the username challenge response.
   *
   * @throws \LogicException
   *   If the username challenge response is requested more than once.
   *
   * @return string
   *   The username challenge response.
   */
  protected function getUsernameChallengeResponse(): string {
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
    $challenge = \reset($response);

    try {
      $result = match ($challenge) {
        'UGFzc3dvcmQ6' => $this->getPasswordChallengeResponse(),
        'VXNlcm5hbWU6' => $this->getUsernameChallengeResponse(),
      };

      return $result;
    }
    catch (\UnhandledMatchError $e) {
      throw new \LogicException('An unknown LOGIN challenge was sent by the remote server: ' . \var_export($challenge, TRUE));
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
