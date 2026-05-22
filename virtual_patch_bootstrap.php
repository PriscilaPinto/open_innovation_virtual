<?php

// Este arquivo deve ser incluído muito cedo no processo de inicialização da aplicação,
// idealmente logo após o autoloader do Composer ser requerido, mas antes que qualquer
// instância de GuzzleHttp\Client seja criada.
//
// Exemplo de uso:
// require __DIR__ . '/vendor/autoload.php';
// require __DIR__ . '/guzzle_virtual_patch.php'; // Este arquivo

// Impede múltiplas aplicações do patch.
if (defined('GUZZLE_VIRTUAL_PATCH_APPLIED')) {
    return;
}

// Garante que as classes principais do Guzzle e PSR-7 estejam disponíveis.
// Isso acionará o autoloader do Composer se as classes ainda não tiverem sido carregadas.
if (!class_exists('GuzzleHttp\\Client') ||
    !class_exists('GuzzleHttp\\HandlerStack') ||
    !class_exists('GuzzleHttp\\Cookie\\CookieJar') ||
    !class_exists('GuzzleHttp\\Cookie\\SetCookie') ||
    !class_exists('GuzzleHttp\\Psr7\\UriResolver') ||
    !class_exists('GuzzleHttp\\Psr7\\Uri') ||
    !interface_exists('Psr\\Http\\Message\\RequestInterface') ||
    !interface_exists('Psr\\Http\\Message\\ResponseInterface') ||
    !interface_exists('Psr\\Http\\Message\\UriInterface')
) {
    // Se alguma classe crítica do Guzzle/PSR-7 não puder ser carregada, o patch não pode ser aplicado.
    // Isso geralmente indica um problema com a configuração do autoloader do Composer ou que o Guzzle não está instalado.
    return;
}

use GuzzleHttp\Psr7\UriResolver;
use GuzzleHttp\Psr7\Uri;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Cookie\SetCookie;

// --- Middleware Personalizado para CVE-2022-31042, CVE-2022-31043, CVE-2022-31091, CVE-2022-31090 ---
// Este middleware personalizado substitui o RedirectMiddleware padrão do Guzzle para corrigir o vazamento de cabeçalhos.
// Ele é baseado nas correções implementadas no Guzzle 6.5.7/7.4.4/7.4.5.
class GuzzleHttpVirtualPatch_SecureRedirectMiddleware
{
    private $nextHandler;

    public function __construct(callable $nextHandler)
    {
        $this->nextHandler = $nextHandler;
    }

    public function __invoke(RequestInterface $request, array $options)
    {
        $fn = $this->nextHandler;

        if (empty($options['allow_redirects'])) {
            return $fn($request, $options);
        }

        $max = 5;
        $strict = false;
        $referer = false;
        $protocols = ['http', 'https'];
        $trackRedirects = false;

        if (is_array($options['allow_redirects'])) {
            $arr = $options['allow_redirects'];
            if (isset($arr['max'])) {
                $max = (int) $arr['max'];
            }
            if (isset($arr['strict'])) {
                $strict = (bool) $arr['strict'];
            }
            if (isset($arr['referer'])) {
                $referer = (bool) $arr['referer'];
            }
            if (isset($arr['protocols'])) {
                $protocols = $arr['protocols'];
            }
            if (isset($arr['track_redirects'])) {
                $trackRedirects = (bool) $arr['track_redirects'];
            }
        }

        if ($max === 0) {
            return $fn($request, $options);
        }

        return $fn($request, $options)->then(
            function (ResponseInterface $response) use ($request, $options, $fn, $max, $strict, $referer, $protocols, $trackRedirects) {
                return $this->checkRedirect($request, $options, $response, $fn, $max, $strict, $referer, $protocols, $trackRedirects);
            }
        );
    }

    private function checkRedirect(
        RequestInterface $request,
        array $options,
        ResponseInterface $response,
        callable $fn,
        $max,
        $strict,
        $referer,
        $protocols,
        $trackRedirects
    ) {
        if ($max === 0) {
            return \GuzzleHttp\Promise\promise_for($response);
        }

        $statusCode = $response->getStatusCode();
        if ($statusCode < 300 || $statusCode >= 400) {
            return \GuzzleHttp\Promise\promise_for($response);
        }

        if (!in_array($statusCode, [301, 302, 303, 307, 308])) {
            return \GuzzleHttp\Promise\promise_for($response);
        }

        $location = $response->getHeaderLine('Location');
        if (empty($location)) {
            return \GuzzleHttp\Promise\promise_for($response);
        }

        $newUri = UriResolver::resolve($request->getUri(), new Uri($location));

        if (!in_array($newUri->getScheme(), $protocols)) {
            return \GuzzleHttp\Promise\promise_for($response);
        }

        // --- CORREÇÕES DE SEGURANÇA PARA REDIRECIONAMENTOS ---
        $originalUri = $request->getUri();
        $stripSensitiveHeaders = false;

        // CVE-2022-31043: Downgrade de HTTPS para HTTP
        if ($originalUri->getScheme() === 'https' && $newUri->getScheme() === 'http') {
            $stripSensitiveHeaders = true;
        }

        // CVE-2022-31042, CVE-2022-31091: Cross-origin (mudança de host ou porta)
        if ($originalUri->getHost() !== $newUri->getHost() || $originalUri->getPort() !== $newUri->getPort()) {
            $stripSensitiveHeaders = true;
        }

        $newRequest = $request;
        if ($stripSensitiveHeaders) {
            // Remove o cabeçalho Authorization (CVE-2022-31043, CVE-2022-31090, CVE-2022-31091)
            $newRequest = $newRequest->withoutHeader('Authorization');
            // Remove o cabeçalho Cookie (CVE-2022-31042, CVE-2022-31091)
            $newRequest = $newRequest->withoutHeader('Cookie');

            // Para CURLOPT_HTTPAUTH (CVE-2022-31090), se foi definido diretamente nas opções,
            // precisamos removê-lo. Esta é uma tentativa de melhor esforço, pois o CurlHandler do Guzzle
            // normalmente gerencia isso com base no cabeçalho Authorization.
            if (isset($options['curl'][CURLOPT_HTTPAUTH])) {
                unset($options['curl'][CURLOPT_HTTPAUTH]);
            }
        }
        // --- FIM DAS CORREÇÕES DE SEGURANÇA PARA REDIRECIONAMENTOS ---

        $newRequest = $newRequest->withUri($newUri);

        if ($newUri->getHost() !== $request->getUri()->getHost()) {
            $newRequest = $newRequest->withoutHeader('Host');
        }

        if ($referer && $newRequest->getUri()->getHost() !== $request->getUri()->getHost()) {
            $newRequest = $newRequest->withHeader('Referer', (string) $request->getUri());
        }

        if ($strict && in_array($statusCode, [301, 302])) {
            $newRequest = $newRequest->withMethod('GET');
            $newRequest = $newRequest->withoutBody();
        }

        if ($trackRedirects) {
            $redirectHistory = isset($options['history']) ? $options['history'] : [];
            $redirectHistory[] = [
                'request' => $request,
                'response' => $response,
            ];
            $options['history'] = $redirectHistory;
        }

        $options['allow_redirects'] = $max - 1;
        return $fn($newRequest, $options)->then(
            function (ResponseInterface $response) use ($newRequest, $options, $fn, $max, $strict, $referer, $protocols, $trackRedirects) {
                return $this->checkRedirect($newRequest, $options, $response, $fn, $max, $strict, $referer, $protocols, $trackRedirects);
            }
        );
    }
}

// --- CookieJar Personalizado para CVE-2022-29248 (Cookies Maliciosos) ---
// Esta classe sobrescreve CookieJar para implementar a lógica de validação de domínio
// do Guzzle 6.5.6/7.4.3 em `extractCookies`.
class GuzzleHttpVirtualPatch_SecureCookieJar extends CookieJar
{
    public function extractCookies(RequestInterface $request, ResponseInterface $response)
    {
        $reqHost = $request->getUri()->getHost();
        $reqPath = $request->getUri()->getPath();

        foreach (SetCookie::fromResponse($response) as $cookie) {
            // Correção CVE-2022-29248: Valida o domínio do cookie em relação ao host da requisição.
            // Esta lógica é baseada na correção oficial do Guzzle.
            if ($cookie->getDomain()) {
                $domain = $cookie->getDomain();
                // Remove o ponto inicial para comparação
                if (strpos($domain, '.') === 0) {
                    $domain = substr($domain, 1);
                }

                // Verifica se o domínio do cookie é um sufixo do host da requisição
                // ou se são idênticos.
                // Isso impede que um servidor malicioso defina cookies para domínios não relacionados.
                if ($domain !== $reqHost && !str_ends_with($reqHost, '.' . $domain)) {
                    // Cookie malicioso detectado, ignorá-lo.
                    continue;
                }
            }

            // O SetCookie::validate() original do Guzzle 6.3.0 apenas verifica a expiração.
            // A validação de domínio é tratada acima.
            if (!$cookie->validate()) {
                continue;
            }

            $this->setCookie($cookie);
        }
    }
}

// --- CookieMiddleware Personalizado ---
// Este middleware garante que nosso SecureCookieJar seja usado quando os cookies estiverem habilitados.
class GuzzleHttpVirtualPatch_SecureCookieMiddleware
{
    private $nextHandler;

    public function __construct(callable $nextHandler)
    {
        $this->nextHandler = $nextHandler;
    }

    public function __invoke(RequestInterface $request, array $options)
    {
        $fn = $this->nextHandler;

        if (empty($options['cookies'])) {
            return $fn($request, $options);
        }

        // Se 'cookies' for true, usa nosso SecureCookieJar. Caso contrário, usa o fornecido.
        $jar = $options['cookies'] === true
            ? new GuzzleHttpVirtualPatch_SecureCookieJar()
            : $options['cookies'];

        if (!($jar instanceof CookieJar)) {
            throw new \InvalidArgumentException('cookies must be an instance of GuzzleHttp\Cookie\CookieJar or true');
        }

        $request = $jar->with($request, $request->getUri()->getHost(), $request->getUri()->getPath());

        return $fn($request, $options)->then(
            function (ResponseInterface $response) use ($jar, $request) {
                $jar->extractCookies($request, $response);
                return $response;
            }
        );
    }
}

// --- GuzzleHttp\Client Corrigido ---
// Esta classe estende o GuzzleHttp\Client original e injeta nossos middlewares personalizados.
// Ela será apelidada para GuzzleHttp\Client para aplicar o patch de forma transparente.
class GuzzleHttpVirtualPatch_PatchedClient extends \GuzzleHttp\Client
{
    public function __construct(array $config = [])
    {
        // Se nenhum handler for fornecido, cria um padrão.
        if (!isset($config['handler'])) {
            $config['handler'] = \GuzzleHttp\HandlerStack::create();
        } elseif (!($config['handler'] instanceof \GuzzleHttp\HandlerStack)) {
            throw new \InvalidArgumentException('handler must be an instance of GuzzleHttp\HandlerStack');
        }

        // Remove o middleware de redirecionamento padrão do Guzzle e adiciona nossa versão segura.
        // O middleware de redirecionamento padrão do Guzzle é tipicamente nomeado 'redirect'.
        $config['handler']->remove('redirect');
        $config['handler']->push(
            new GuzzleHttpVirtualPatch_SecureRedirectMiddleware(
                $config['handler']->resolve()
            ),
            'redirect'
        );

        // Remove o middleware de cookie padrão do Guzzle e adiciona nossa versão segura.
        // O middleware de cookie padrão do Guzzle é tipicamente nomeado 'cookies'.
        $config['handler']->remove('cookies');
        $config['handler']->push(
            new GuzzleHttpVirtualPatch_SecureCookieMiddleware(
                $config['handler']->resolve()
            ),
            'cookies'
        );

        // Chama o construtor original do GuzzleHttp\Client com a configuração modificada.
        // Precisamos garantir que o GuzzleHttp\Client original esteja disponível sob seu nome original
        // para a chamada do construtor pai, mesmo após o aliasing.
        // Isso é tratado pelo mecanismo `class_alias` abaixo, onde a classe original
        // é temporariamente apelidada para `GuzzleHttpVirtualPatch_OriginalClient`.
        parent::__construct($config);
    }
}

// --- Aplica o Patch Virtual usando class_alias ---
// Este mecanismo substitui transparentemente GuzzleHttp\Client pela nossa versão corrigida.
// Ele requer que a classe GuzzleHttp\Client original seja carregada pelo autoloader do Composer
// antes que este alias seja feito.

// Verifica se a classe GuzzleHttp\Client já está definida.
if (class_exists('GuzzleHttp\\Client', false)) {
    // Se já estiver definida, precisamos apelidá-la primeiro para um nome temporário.
    // Isso lida com casos em que GuzzleHttp\Client pode ter sido carregado antes do nosso patch.
    if (!class_exists('GuzzleHttpVirtualPatch_OriginalClient', false)) {
        class_alias('GuzzleHttp\\Client', 'GuzzleHttpVirtualPatch_OriginalClient', false);
    }
    // Em seguida, apelida nosso cliente corrigido para o nome original.
    // Isso garante que `GuzzleHttp\Client` agora aponte para nossa versão corrigida.
    // O `parent::__construct` em `GuzzleHttpVirtualPatch_PatchedClient` se referirá corretamente
    // a `GuzzleHttpVirtualPatch_OriginalClient`.
    class_alias('GuzzleHttpVirtualPatch_PatchedClient', 'GuzzleHttp\\Client', false);
} else {
    // Se GuzzleHttp\Client ainda não estiver definida, podemos apelidar diretamente nosso cliente corrigido
    // para o nome original. Quando `GuzzleHttp\Client` for posteriormente carregado automaticamente
    // (por exemplo, por `parent::__construct`), ele carregará a classe original.
    class_alias('GuzzleHttpVirtualPatch_PatchedClient', 'GuzzleHttp\\Client', false);
}

// Marca o patch como aplicado para evitar reaplicação.
define('GUZZLE_VIRTUAL_PATCH_APPLIED', true);

// O patch agora está ativo. Quaisquer novas chamadas `new GuzzleHttp\Client()`
// instanciarão `GuzzleHttpVirtualPatch_PatchedClient` que usa nossos middlewares seguros.