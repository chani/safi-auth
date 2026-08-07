<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\ValueObject\PhpVersion;

$paths = [__DIR__ . '/src'];
if (is_dir(__DIR__ . '/tests')) {
    $paths[] = __DIR__ . '/tests';
}
if (is_dir(__DIR__ . '/components')) {
    $paths[] = __DIR__ . '/components';
}

return RectorConfig::configure()
    ->withPaths($paths)
    ->withSkip([
        '*/vendor/*',
        '*/data/*',
        '*/cache/*',
        '*/var/*',
        '*/storage/*',
    ])
    ->withPhpVersion(PhpVersion::PHP_85)
    ->withPreparedSets(
        deadCode: true,
        codeQuality: true,
        typeDeclarations: true,
        earlyReturn: true,
    );
