<?php

declare(strict_types=1);

namespace LibraryMarket\msadiag\SMTP;

/**
 * Describes an SMTP connection type.
 *
 * @phpcs:disable Drupal.NamingConventions.ValidEnumCase.NoUpperAcronyms
 */
enum ConnectionType {

  case Auto;
  case PlainText;
  case STARTTLS;
  case TLS;

}
