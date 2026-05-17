<?php

require 'vendor/autoload.php';

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

$guzzleOptions = [
    'cookies' => false,
    'allow_redirects' => false,
];

$client = new Client($guzzleOptions);

try {
    $response = $client->request('GET', 'https://api.github.com');

    echo "Status da API: " . $response->getStatusCode();

} catch (RequestException $e) {
    if ($e->hasResponse()) {
        $statusCode = $e->getResponse()->getStatusCode();
        if ($statusCode >= 300 && $statusCode < 400) {
            echo "Erro: Redirecionamento detectado (Status " . $statusCode . "). Redirecionamentos estão desabilitados por segurança para prevenir vazamento de informações.";
        } else {
            echo "Erro na requisição: " . $e->getMessage();
        }
    } else {
        echo "Erro de rede ou requisição: " . $e->getMessage();
    }
} catch (Exception $e) {
    echo "Erro inesperado: " . $e->getMessage();
}