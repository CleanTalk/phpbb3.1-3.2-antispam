<?php

/**
 * Builds the package for the phpBB Customisation Database.
 *
 * Usage: php build/package.php [--no-epv]
 *
 * Copies cleantalk/antispam into build/out/package/cleantalk/antispam without
 * development files, runs the Extension Pre Validator (EPV) on it when available
 * and zips the result to build/out/cleantalk_antispam_<version>.zip.
 */

$root = dirname(__DIR__);
$source = $root . '/cleantalk/antispam';
$out = __DIR__ . '/out';
$staging = $out . '/package';
$target = $staging . '/cleantalk/antispam';

// Paths relative to cleantalk/antispam
$excluded_paths = array(
    'vendor',
    'composer.lock',
    'cleantalk_fw_files',
);

// Names excluded at any depth
$excluded_names = array(
    '.git',
    '.github',
    '.gitignore',
    '.gitattributes',
    '.editorconfig',
    'tests',
    'phpunit.xml',
    'phpunit.xml.dist',
    'psalm.xml',
    '.phpcs.xml',
);

/**
 * @param string $path
 * @return void
 */
function remove_dir($path)
{
    if (!is_dir($path)) {
        return;
    }
    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($items as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }
    rmdir($path);
}

/**
 * @param string $relative Path relative to cleantalk/antispam, with forward slashes
 * @param array $excluded_paths
 * @param array $excluded_names
 * @return bool
 */
function is_excluded($relative, array $excluded_paths, array $excluded_names)
{
    foreach ($excluded_paths as $path) {
        if ($relative === $path || strpos($relative, $path . '/') === 0) {
            return true;
        }
    }

    $parts = explode('/', $relative);
    if (array_intersect($parts, $excluded_names)) {
        return true;
    }

    // EPV accepts a single composer.json, the one of the extension
    return basename($relative) === 'composer.json' && $relative !== 'composer.json';
}

$composer = json_decode(file_get_contents($source . '/composer.json'), true);
$version = isset($composer['version']) ? $composer['version'] : 'dev';

remove_dir($staging);
mkdir($target, 0777, true);

$files = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
);
$copied = 0;
foreach ($files as $file) {
    $relative = str_replace('\\', '/', substr($file->getPathname(), strlen($source) + 1));
    if (is_excluded($relative, $excluded_paths, $excluded_names)) {
        continue;
    }
    $destination = $target . '/' . $relative;
    if ($file->isDir()) {
        if (!is_dir($destination)) {
            mkdir($destination, 0777, true);
        }
        continue;
    }
    if (!is_dir(dirname($destination))) {
        mkdir(dirname($destination), 0777, true);
    }
    copy($file->getPathname(), $destination);
    $copied++;
}
echo "Copied $copied files to $target\n";

$epv = $source . '/vendor/phpbb/epv/src/EPV.php';
$epv_failed = false;
if (!in_array('--no-epv', $argv, true)) {
    if (file_exists($epv)) {
        echo "Running EPV...\n";
        // EPV exits with 0 even when validation fails, so check its summary instead
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($epv) . ' run --dir=' . escapeshellarg($staging) . ' 2>&1', $epv_output);
        echo implode("\n", $epv_output) . "\n";
        $epv_failed = (bool) preg_grep('/Validation: FAILED/', $epv_output);
    } else {
        echo "EPV not found. Install it with: composer install -d cleantalk/antispam\n";
    }
}

$zip_path = $out . '/cleantalk_antispam_' . $version . '.zip';
if (file_exists($zip_path)) {
    unlink($zip_path);
}
$zip = new ZipArchive();
if ($zip->open($zip_path, ZipArchive::CREATE) !== true) {
    fwrite(STDERR, "Cannot create $zip_path\n");
    exit(1);
}
$files = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($staging, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
);
foreach ($files as $file) {
    $relative = str_replace('\\', '/', substr($file->getPathname(), strlen($staging) + 1));
    $file->isDir() ? $zip->addEmptyDir($relative) : $zip->addFile($file->getPathname(), $relative);
}
$zip->close();
echo "Package: $zip_path\n";

exit($epv_failed ? 1 : 0);
