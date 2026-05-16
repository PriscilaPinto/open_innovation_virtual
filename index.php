<?php

require 'vendor/autoload.php';

use GuzzleHttp\Client;

$client = new Client([
    'allow_redirects' => false,
    'cookies' => false,
]);

try {
    $response = $client->request('GET', 'https://api.github.com');

    echo "Status da API: " . $response->getStatusCode();

} catch (Exception $e) {

    echo "Erro: " . $e->getMessage();
}