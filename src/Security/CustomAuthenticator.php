<?php
namespace App\Security;


use Lexik\Bundle\JWTAuthenticationBundle\Security\Authenticator\JWTAuthenticator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

class CustomAuthenticator extends JWTAuthenticator
{
    // Your own logic
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception):JsonResponse
    {
        $data = array(
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData()),
        );

        return new JsonResponse($data, 200);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        dump($user);

        die;
    }
}