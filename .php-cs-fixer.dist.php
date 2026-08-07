<?php

declare(strict_types=1);

use PhpCsFixer\Config;
use PhpCsFixer\Finder;

$finder = (new Finder())
    ->in([__DIR__ . '/src'])
    ->exclude(['vendor', 'data', 'cache', 'var', 'storage'])
    ->notName('*.cache')
    ->append([__FILE__]);

if (is_dir(__DIR__ . '/tests')) {
    $finder->in(__DIR__ . '/tests');
}
if (is_dir(__DIR__ . '/components')) {
    $finder->in(__DIR__ . '/components');
}

return (new Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@PER-CS2.0' => true,
        '@PER-CS2.0:risky' => true,
        'declare_strict_types' => true,
        'array_syntax' => ['syntax' => 'short'],
        'ordered_imports' => [
            'sort_algorithm' => 'alpha',
            'imports_order' => ['class', 'function', 'const'],
        ],
        'no_unused_imports' => true,
        'single_line_after_imports' => true,
        'trailing_comma_in_multiline' => [
            'elements' => ['arrays', 'arguments', 'parameters', 'match'],
        ],
        'nullable_type_declaration_for_default_null_value' => true,
        'modernize_types_casting' => true,
        'no_superfluous_phpdoc_tags' => [
            'remove_inheritdoc' => true,
            'allow_mixed' => true,
        ],
    ])
    ->setFinder($finder);
