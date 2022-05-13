<?php

declare(strict_types = 1);

namespace LibraryMarket\msadiag\SMTP;

/**
 * Describes a client greeting type.
 */
enum ClientGreetingType: string {

  case Basic = 'HELO';
  case Extended = 'EHLO';

}
