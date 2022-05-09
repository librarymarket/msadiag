<?php

declare(strict_types = 1);

namespace LibraryMarket\mstt\SMTP;

/**
 * Describes an SMTP connection type.
 */
enum ConnectionType {

  case PlainText;
  case STARTTLS;
  case TLS;

}
