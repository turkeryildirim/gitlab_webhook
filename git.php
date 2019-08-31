<?php
// remote repo ssh url to be verified
$config_remote = 'git@gitlab.domain.com.tr:turkeryildirim/gitlab_webhook.git';

// full path of the local folder
$config_locals = [
    'staging' => '/home/staging/public_html',
    'master'  => '/home/production/public_html',
];

// tracking branch to be deployed to local
$config_branch = [ 'staging', 'master' ];

// tracking event
$config_action = 'push';

// secret word will be used in webhook url
$config_secret = 'secret';

// token weill be used in Post header
$config_token = 'token';

// allowed gitlab usernames, * means all
$config_allowed_users = [ '*' ];

// allow connections from
$config_ip_white_list = [
    '54.36.180.117',
    '127.0.0.1',
];

// executables
$config_php_bin_path      = '/usr/bin/php';
$config_git_bin_path      = '/usr/bin/git';
$config_composer_bin_path = '/usr/bin/composer';

/* ========================================================================================================== */
if (! isset($_GET['secret']) || $_GET['secret'] != $config_secret) {
    die('No access');
}

$required_keys = [
    'X-Gitlab-Token',
    'X-Gitlab-Event',
    'Content-Type',
    'Content-Length',
];

$headers = getheaders();
if (count(array_intersect_key(array_flip($required_keys), $headers)) != count($required_keys)) {
    die('Missing key(s) in header');
}

if (! isset($headers['X-Gitlab-Token']) || $headers['X-Gitlab-Token'] != $config_token) {
    die('No access');
}

if ($config_action == 'push' && $headers['X-Gitlab-Event'] != 'Push Hook') {
    die('No PUSH event, instead: ' . $headers['X-Gitlab-Event']);
}

if (! check_ip_white_list($_SERVER['REMOTE_ADDR'], $config_ip_white_list)) {
    die('Request IP is not in white list');
}

$payload = file_get_contents('php://input');
if (empty($payload)) {
    die('No PAYLOAD');
}

if (! $payload = json_decode($payload)) {
    die('Json issue');
}

if ($config_allowed_users[0] != '*') {
    if (! in_array($payload->username, $config_allowed_users)) {
        die($payload->user_username . ' does not have access rights');
    }
}

if ($payload->repository->git_ssh_url != $config_remote) {
    die($payload->repository->git_ssh_url . ' is not a correct repository');
}

$ref = str_replace('refs/heads/', '', $payload->ref);
if (! in_array($ref, $config_branch)) {
    die($payload->ref . ' is not a matching branch');
}

$dir = $config_locals[ $ref ];

if (__DIR__ != $dir) {
    die($dir . ' is not a correct directory for ' . $ref);
}

$x1 = shell_exec('cd ' . $dir . ' && ' . $config_git_bin_path . ' fetch 2>&1');
$x2 = shell_exec('cd ' . $dir . ' && ' . $config_git_bin_path . ' checkout ' . $ref . ' 2>&1');
$x3 = shell_exec('cd ' . $dir . ' && ' . $config_git_bin_path . ' pull origin ' . $ref . ' 2>&1');
//$x4 = shell_exec( 'cd ' . $dir . ' && ' . $config_composer_bin_path . ' dumpautoload 2>&1' );
var_dump($x1, $x2, $x3);


function getheaders()
{
    $headers = [];
    foreach ($_SERVER as $name => $value) {
        if (substr($name, 0, 5) == 'HTTP_') {
            $name             = str_replace(
                ' ',
                '-',
                ucwords(strtolower(str_replace('_', ' ', substr($name, 5))))
            );
            $headers[ $name ] = $value;
        } elseif ($name == 'CONTENT_TYPE') {
            $headers['Content-Type'] = $value;
        } elseif ($name == 'CONTENT_LENGTH') {
            $headers['Content-Length'] = $value;
        } elseif ($name == 'USER_AGENT') {
            $headers['User-Agent'] = $value;
        }
    }

    return $headers;
}

function check_ip_white_list($remote_ip, $ip_white_list)
{
    if (empty($ip_white_list)) {
        return true;
    }

    $new_list = [];
    foreach ($ip_white_list as $ip) {
        if (stristr($ip, '/')) {
            if (ip_in_range($remote_ip, $ip)) {
                return true;
            }
        } else {
            $new_list[] = $ip;
        }
    }

    return in_array($remote_ip, $new_list);
}

function ip_in_range($ip, $range)
{
    if (strpos($range, '/') == false) {
        $range .= '/32';
    }
    // $range is in IP/CIDR format eg 127.0.0.1/24
    list( $range, $netmask ) = explode('/', $range, 2);
    $range_decimal    = ip2long($range);
    $ip_decimal       = ip2long($ip);
    $wildcard_decimal = pow(2, ( 32 - $netmask )) - 1;
    $netmask_decimal  = ~$wildcard_decimal;

    return ( $ip_decimal & $netmask_decimal ) == ( $range_decimal & $netmask_decimal );
}
