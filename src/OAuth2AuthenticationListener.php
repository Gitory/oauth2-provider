<?php

namespace Gitory\OAuth2;

use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use OAuth2\Server;
use OAuth2\HttpFoundationBridge\Request as BridgeRequest;
use OAuth2\HttpFoundationBridge\Response as BridgeResponse;
use Psr\Log\LoggerInterface;

class OAuth2AuthenticationListener
{
    private $oauth2Server;
    private $securityContext;
    private $authenticationManager;
    private $providerKey;
    private $authenticationEntryPoint;
    private $logger;
    private $ignoreFailure;

    public function __construct(
        Server $oauth2Server,
        SecurityContextInterface $securityContext,
        AuthenticationManagerInterface $authenticationManager,
        $providerKey,
        AuthenticationEntryPointInterface $authenticationEntryPoint,
        LoggerInterface $logger = null
    ) {
        $this->oauth2Server = $oauth2Server;

        if (empty($providerKey)) {
            throw new \InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->providerKey = $providerKey;
        $this->authenticationEntryPoint = $authenticationEntryPoint;
        $this->logger = $logger;
        $this->ignoreFailure = false;
    }

    /**
     * Handles basic authentication.
     *
     * @param GetResponseEvent $event A GetResponseEvent instance
     */
    public function handle(GetResponseEvent $event)
    {
        $request = BridgeRequest::createFromRequest($event->getRequest());
        $response = new BridgeResponse;

        if (!$this->oauth2Server->verifyResourceRequest($request, $response)) {
            return;
        }

        try {
            $token = $this->authenticationManager->authenticate(new OAuth2Token([]));
            $this->securityContext->setToken($token);
        } catch (AuthenticationException $failed) {
            $token = $this->securityContext->getToken();
            if ($token instanceof OAuth2Token) {
                $this->securityContext->setToken(null);
            }

            if (null !== $this->logger) {
                $this->logger->info(sprintf('Authentication request failed for user "%s": %s', $username, $failed->getMessage()));
            }

            if ($this->ignoreFailure) {
                return;
            }

            $event->setResponse($this->authenticationEntryPoint->start($request, $failed));
        }
    }
}
