<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Attributes;

use Attribute;

#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final readonly class Permission
{
    public function __construct(
        public string $key,
        public string $label = '',
        public string $category = 'general',
    ) {}
}
