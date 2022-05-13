<?php

declare(strict_types = 1);

namespace LibraryMarket\msadiag\SMTP;

/**
 * Describes an SMTP connection type.
 */
enum ConnectionType {

  case Auto;
  case PlainText;
  case STARTTLS;
  case TLS;

}
