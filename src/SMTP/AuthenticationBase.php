<?php

declare(strict_types = 1);

namespace LibraryMarket\mstt\SMTP;

/**
 * A base implementation for a SASL authentication mechanism.
 */
abstract class AuthenticationBase implements AuthenticationInterface {

  /**
   * {@inheritdoc}
   */
  public function reset(): void {
  }

}
