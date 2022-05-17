<?php

declare(strict_types = 1);

namespace LibraryMarket\msadiag\Attribute;

#[\Attribute]
/**
 * An attribute used to identify a validation test method.
 */
class ValidationTest {

  /**
   * A description of the validation test method.
   *
   * @var string
   */
  public string $description;

  /**
   * Whether the test constitutes a strict test.
   *
   * @var bool
   */
  public bool $strict;

  /**
   * Constructs a ValidationTest object.
   *
   * @param string $description
   *   A description of the validation test method.
   * @param bool $strict
   *   Whether the test constitutes a strict test.
   */
  public function __construct(string $description, bool $strict = FALSE) {
    $this->description = $description;
    $this->strict = $strict;
  }

}
