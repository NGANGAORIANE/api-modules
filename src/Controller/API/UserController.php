<?php

namespace App\Controller\API;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class UserController extends AbstractController
{

    #[Route('/login', name: 'api_login_custom', methods: ['POST'])]
    public function login(EntityManagerInterface $em,
        JWTTokenManagerInterface $JWTManager, 
        Request $request,
        UserPasswordHasherInterface $hasher
        ): JsonResponse
    
    {
        $data = json_decode($request->getContent(), true);
        $user = $em->getRepository(User::class)->findOneBy(['email' => $data['email']]);

        if (!$user || !$hasher->isPasswordValid($user, $data['password'])) 
            return new JsonResponse(['error' => 'Identifiants incorrects'], 401);
        
        // Générer un token JWT
        $token = $JWTManager->create($user);

        return new JsonResponse(['token' => $token]) ;
    }

    #[Route('/api/me', name: 'api_me')]
    #[IsGranted("ROLE_USER")]
    public function me(): JsonResponse
    {
        // Retrieve the authenticated user
        $user = $this->getUser();

        if (!$user instanceof UserInterface) {
            return new JsonResponse(['error' => 'Unauthorized'], 401);
        }

        return new JsonResponse([
            'roles' => $user->getRoles(),
            'firstName' => $user->getFirstName(),
            'email' =>  $user->getUserIdentifier(),
        ]);
    }
}
