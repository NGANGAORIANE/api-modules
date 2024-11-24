// src/Controller/AuthController.php

namespace src\Controller;

use src\Entity\User;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Security;

class AuthController extends AbstractController
{
    private $jwtManager;
    private $passwordEncoder;
    private $security;

    // Injecter les dépendances nécessaires
    public function __construct(JWTTokenManagerInterface $jwtManager, UserPasswordEncoderInterface $passwordEncoder, Security $security)
    {
        $this->jwtManager = $jwtManager;
        $this->passwordEncoder = $passwordEncoder;
        $this->security = $security;
    }

    /**
     * @Route("/api/login", name="api_login", methods={"POST"})
     */
    public function login(Request $request): JsonResponse
    {
        // Récupérer les données de la requête (username et password)
        $data = json_decode($request->getContent(), true);

        // Valider si les données sont présentes
        if (empty($data['username']) || empty($data['password'])) {
            return new JsonResponse(['message' => 'Username and password required'], JsonResponse::HTTP_BAD_REQUEST);
        }

        // Récupérer l'utilisateur en fonction du nom d'utilisateur
        $user = $this->getDoctrine()->getRepository(User::class)->findOneBy(['username' => $data['username']]);

        // Vérifier si l'utilisateur existe
        if (!$user) {
            return new JsonResponse(['message' => 'Invalid credentials'], JsonResponse::HTTP_UNAUTHORIZED);
        }

        // Vérifier si le mot de passe est correct
        if (!$this->passwordEncoder->isPasswordValid($user, $data['password'])) {
            return new JsonResponse(['message' => 'Invalid credentials'], JsonResponse::HTTP_UNAUTHORIZED);
        }

        // Générer le JWT
        $token = $this->jwtManager->create($user);

        // Retourner le token dans la réponse
        return new JsonResponse(['token' => $token]);
    }

    /**
     * @Route("/api/user", name="api_user", methods={"GET"})
     */
    public function getUser(): JsonResponse
    {
        // Récupérer l'utilisateur connecté
        $user = $this->getUser();

        // Si l'utilisateur est connecté, renvoyer ses informations
        if ($user instanceof UserInterface) {
            return new JsonResponse([
                'username' => $user->getUsername(),
                'roles' => $user->getRoles(),
            ]);
        }

        // Si l'utilisateur n'est pas connecté, renvoyer une erreur
        return new JsonResponse(['message' => 'User not authenticated'], JsonResponse::HTTP_UNAUTHORIZED);
    }
}
