<?php

namespace Gitory\OAuth2;

interface AuthorizeRenderer
{
    public function render($formUrl, $clientId, $responseType, $user);
}
